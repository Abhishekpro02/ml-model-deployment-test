import os
import logging
import json
from typing import Union, List, Dict, Any, Optional
from openai import OpenAI, AsyncOpenAI, OpenAIError, RateLimitError, APIConnectionError
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
import asyncio
import argparse
from pydantic import BaseModel, conint, Field, validator, ValidationError
import difflib
import hashlib

from semgrep_util import run_semgrep
from treeChunk import CodeChunker
from analysis.caching import AnalysisCache, analysis_cache
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


# Import logging configuration
from logging_config import setup_logging

# Set up logging
setup_logging()
logger = logging.getLogger(__name__)

# Load sensitive data from environment variables
API_KEY = os.getenv('API_KEY')
client = AsyncOpenAI(api_key=API_KEY)

if not API_KEY:
    raise ValueError("API key not found. Please set the OPENAI_API_KEY environment variable.")

@retry(
    retry=retry_if_exception_type((RateLimitError, APIConnectionError)),  # Retry only on these errors
    wait=wait_exponential(multiplier=1, min=2, max=10),  # Exponential backoff (2s, 4s, 8s, max 10s)
    stop=stop_after_attempt(3)  # Stop after 3 attempts
)

# Pydantic models for structured responses
class VulLine(BaseModel):
    lineNum: int
    lineCode: str


class DetectionResult(BaseModel):
    language: str
    is_vulnerability: bool
    vulnerabilityType: str
    cwe: str
    vulnerabilityLines: List[VulLine]
    riskLevel: Union[float, str] = Field(..., description="CVSS-like risk score (0-10) or severity label.")
    explanation: str
    fixCode: str

    @validator("riskLevel", pre=True)
    def convert_risk_level(cls, value):
        """Convert risk level from string labels to CVE-like numeric scores."""
        severity_mapping = {
            'N/a': 'None',
            "None": 0.0,
            "Low": 1.0,
            "Medium": 4.0,
            "High": 7.0,
            "Critical": 9.0
        }

        if isinstance(value, str) and value.isdigit():
            value = int(value)

        if isinstance(value, str):
            value = value.capitalize()  # Normalize input (e.g., "medium" → "Medium")
            if value in severity_mapping:
                return severity_mapping[value]
            raise ValueError(
                f"Invalid risk level '{value}'. Use a number (0-10) or labels: {list(severity_mapping.keys())}.")

        if not (0.0 <= value <= 10.0):
            raise ValueError("Risk level must be between 0 and 10.")

        return value

    @classmethod
    def validate_response(cls, response_data: Dict[str, Any]) -> "DetectionResult":
        """Validates and converts API response into a DetectionResult object."""
        try:
            return cls(**response_data)
        except ValidationError as e:
            logger.error(f"Validation error in API response: {e.json()}")
            return None


async def analyze_code_vulnerability(code_snippet: str,
                                     semgrep_results=None,
                                     lang=None  # Now actually used
                                     ) -> Union[DetectionResult, dict]:
    """
    Analyze a code snippet for vulnerabilities using OpenAI's API.
    Asynchronously calls GPT API for vulnerability analysis with retries.

    Args:
        code_snippet (str): The code snippet to analyze.
        use_semgrep: use static analyze to furter

    Returns:
        Union[DetectionResult, dict]: The structured analysis result or an error message.
    """
    # Generate cache key, and check cache

    cache_key = hashlib.sha256(
        f"{code_snippet}{json.dumps(semgrep_results or [])}".encode()
    ).hexdigest()

    # Check cache
    if cached := await analysis_cache.get(cache_key):
        logger.debug("Returning cached analysis")
        return cached

    if cached := await analysis_cache.get(cache_key):
        logger.debug("Returning cached analysis")
        return cached


    try:
        semgrep_info = ""
        if semgrep_results:
            semgrep_info = "\n\n### Semgrep Findings:\n"
            for result in semgrep_results:
                semgrep_info += f"- Rule: {result.get('check_id')}\n"
                semgrep_info += f"  - Issue: {result.get('extra', {}).get('message', 'No description')}\n"
                semgrep_info += f"  - Line: {result.get('start', {}).get('line', 'Unknown')}\n"

        prompt = (
            f""""
                You are an advanced cybersecurity expert proficient in all programming languages. 
                Make sure to check the findings from Semgrep (provided below), but don't rely entirely on them. Use your expertise to identify any potential vulnerabilities that Semgrep may have missed or incorrectly flagged.
                Analyze the following code snippet at the function level to identify vulnerabilities.
                Internally, perform a hidden chain-of-thought reasoning process over the code’s property graph—including its Abstract Syntax Tree (AST), Control Flow Graph (CFG), and Program Dependence Graph (PDG)—but do not include any of that internal reasoning in your final response.

                Following the steps for output.

                1. Based on the programming language {lang}  of the code snippet, analyze the code for any vulnerabilities or security issues, especially against top CWE 30.
                2. If vulnerabilities are found:
                   - Specify the type of vulnerability.
                   - Map vulnerabilities to CWE categories.
                   - Identify the vulnerable lines of code with the line numbers and the actual code.
                   - Provide a detailed explanation of why these lines are vulnerable and the potential risks
                   - Suggest efficient fixes for the vulnerable lines based on best practices in the identified programming language, *return the entire code block with the fix** included (not just the modified lines)
                3. Format your entire response as valid JSON.
                

                ### Code to analyze:
                {code_snippet}

                {semgrep_info}  # Add Semgrep findings to GPT for context.
                """
        )


        response = await client.beta.chat.completions.parse(
            model="gpt-4o-2024-11-20", # gpt-4o-2024-08-06
            messages=[
                {"role": "system", "content": "You are a cybersecurity expert."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.1,
            top_p=0.8,
            seed=42,
            response_format=DetectionResult
        )
        result = response.choices[0].message.parsed
        logger.info("Vulnerability analysis completed successfully.")
        return result

    except RateLimitError as e:
        logger.error("Rate limit exceeded. Retrying...")
        raise e  # Retry due to @retry decorator

    except APIConnectionError as e:
        logger.error("Network error. Retrying...")
        raise e  # Retry due to @retry decorator

    except OpenAIError as e:
        logger.error(f"OpenAI API error: {str(e)}")
        return {"error": str(e)}  # Don't retry if it's a fatal API error

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        return {"error": str(e)}  # Catch-all for unexpected issues


def generate_commit_view_diff(old_code: str, new_code: str) -> str:
    """
    Generate a GitHub commit view diff in Markdown format.

    Args:
        old_code (str): The original code snippet.
        new_code (str): The modified code snippet.

    Returns:
        str: A Markdown-formatted string representing the commit-style diff.
    """
    old_lines = old_code.splitlines()
    new_lines = new_code.splitlines()

    # Generate the unified diff
    diff = difflib.unified_diff(
        old_lines, new_lines, lineterm="", fromfile="Old Code", tofile="New Code"
    )

    # Format the diff in Markdown
    markdown_diff = "```diff\n"  # Start a diff code block
    for line in diff:
        if line.startswith("+++ ") or line.startswith("--- "):  # File header lines
            continue  # Skip these lines to focus on content
        elif line.startswith("+"):  # Added line
            markdown_diff += f"+ {line[1:]}\n"
        elif line.startswith("-"):  # Deleted line
            markdown_diff += f"- {line[1:]}\n"
        else:  # Context (unchanged) lines
            markdown_diff += f"  {line}\n"
    markdown_diff += "```"  # End the diff code block

    return markdown_diff


def normalize_code(code: str) -> str:
    """
    Normalize the code by:
    - Stripping leading/trailing whitespace
    - Standardizing line endings
    - Collapsing excessive blank lines
    """
    lines = code.strip().splitlines()
    normalized = [line.strip() for line in lines if line.strip()]  # Remove blank lines
    return "\n".join(normalized)


def filter_relevant_lines(diff: list, relevant_line_nums: list) -> list:
    """
    Filter the diff to include only relevant lines based on line numbers.
    """
    filtered_diff = []
    for i, line in enumerate(diff):
        line_num = i + 1
        if line_num in relevant_line_nums or line.startswith(("+", "-")):
            filtered_diff.append(line)
    return filtered_diff


def generate_incident_diff(old_code: str, new_code: str, relevant_lines: list[int]) -> str:
    """
    Generate a diff for an incident based on highlighted vulnerable lines.
    """
    # Normalize the input code
    old_code = normalize_code(old_code)
    new_code = normalize_code(new_code)

    # Compute the diff
    diff = list(difflib.unified_diff(
        old_code.splitlines(),
        new_code.splitlines(),
        lineterm="",
        fromfile="Old Code",
        tofile="New Code"
    ))

    # Filter to only include relevant lines
    filtered_diff = filter_relevant_lines(diff, relevant_lines)

    # Format the diff as a Markdown block
    markdown_diff = "```diff\n" + "\n".join(filtered_diff) + "\n```"
    return markdown_diff

async def run_detection_no_context(code_snippet: str, lang: str, static_scan=False):
    """
    Main function to demonstrate vulnerability analysis.
    """

    scan_results = []
    # Step 1: Detect the language

    if not lang:
        logger.error("Could not detect language.")
        semgrep_results = None
    else:

        logger.info(f"Detected language: {lang}")
        logger.info("Starting vulnerability analysis...")

        # Step 2: Run Semgrep on the code
        if static_scan:
            semgrep_results = run_semgrep(code_snippet, lang)
        else:
            semgrep_results = None


    if semgrep_results:
        logger.info(f"Semgrep found {len(semgrep_results)} potential issues. Passing to GPT.")
        result = await analyze_code_vulnerability(code_snippet, semgrep_results, lang)
    else:
        logger.info("Semgrep found no issues. Proceeding with GPT analysis.")
        result = await analyze_code_vulnerability(code_snippet, '', lang)


    if isinstance(result, DetectionResult):
        logger.info(json.dumps(result.model_dump(), indent=4))
        scan_results.append(result)
    else:
        logger.error("Analysis failed with error: %s", result.get("error"))



    return scan_results


def combine_chunks(chunks: List[Dict], max_chars: int = 4000) -> List[Dict]:
    """
    Combine function chunks into larger batches per file, not exceeding max_chars.
    Each combined chunk will contain functions from the same file.
    """
    from collections import defaultdict

    combined_batches = []
    chunks_by_file = defaultdict(list)

    # Group chunks by file
    for chunk in chunks:
        chunks_by_file[chunk['file_path']].append(chunk)

    for file_path, file_chunks in chunks_by_file.items():
        current_batch = ""
        metadata = []
        delimiter = "\n\n-----\n\n"

        for chunk in file_chunks:
            function_text = chunk['function_code']
            # Check if adding this function would exceed max_chars.
            if len(current_batch) + len(delimiter) + len(function_text) > max_chars:
                combined_batches.append({
                    'combined_code': current_batch,
                    'functions': metadata,
                    'lang': chunk['lang'],
                    'file_path': file_path
                })
                current_batch = ""
                metadata = []
            if current_batch:
                current_batch += delimiter
            current_batch += function_text
            # Store metadata for reference
            metadata.append({
                'file_path': chunk['file_path'],
                'start_line': chunk['start_line'],
                'end_line': chunk['end_line']
            })
        if current_batch:
            combined_batches.append({
                'combined_code': current_batch,
                'functions': metadata,
                'lang': file_chunks[0]['lang'],
                'file_path': file_path
            })
    return combined_batches


async def process_batch(batch: Dict, semaphore: asyncio.Semaphore, static_scan: bool = False) -> Dict:
    """
    Processes a combined batch of function chunks.
    """
    async with semaphore:
        vulnerabilities = await run_detection_no_context(batch['code'], batch['lang'], static_scan)
        result = {
            'function_code': batch['code'],
            'start_line': batch['start_line'],
            'end_line': batch['end_line'],
            'file_path': batch['file_path'],
            'hash': batch['hash'],
            'vulnerabilities': vulnerabilities
        }
        return result


async def process_and_scan_codebase_batched(chunker: CodeChunker, directory: str,
                                            file_extensions: List[str],
                                            exclude_dirs: list[str],
                                            max_concurrent: int = 5,
                                            static_scan: bool = False) -> List[Dict]:
    """
    Processes the codebase to extract function chunks, combines them into larger batches (by character limit),
    and then processes these batches concurrently using the vulnerability scanner.
    """
    all_chunks = chunker.chunk_codebase(directory, file_extensions, exclude_dirs)
    # combined_batches = combine_chunks(all_chunks, max_chars=batch_size_chars)
    semaphore = asyncio.Semaphore(max_concurrent)

    tasks = [process_batch(batch, semaphore, static_scan) for batch in all_chunks]
    results = await asyncio.gather(*tasks)

    return results

def load_config(config_file: str) -> Dict:
    """
    Loads the YAML configuration file.
    """
    import yaml
    with open(config_file, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def serialize_pydantic(obj: Any) -> Any:
    """
    Recursively converts Pydantic models within a nested structure to dictionaries.
    """
    if isinstance(obj, BaseModel):
        return obj.dict()
    elif isinstance(obj, list):
        return [serialize_pydantic(item) for item in obj]
    elif isinstance(obj, dict):
        return {key: serialize_pydantic(value) for key, value in obj.items()}
    else:
        return obj

def save_results(results: List[Dict], output_file: str):
    """
    Saves the detection results to a JSON file.
    Converts Pydantic models within the results to dictionaries before serialization.
    """
    # Recursively serialize Pydantic models
    results_serializable = serialize_pydantic(results)

    # Write the serialized results to a JSON file
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(results_serializable, f, indent=2)


def main2():
    # Set up logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')

    # Parse command-line arguments
    parser_arg = argparse.ArgumentParser(description="Code Vulnerability Scanner")
    parser_arg.add_argument("--config", type=str, default="config.yaml", help="Path to configuration file")
    args = parser_arg.parse_args()

    # Load configuration
    config = load_config(args.config)
    scan_config = config.get('scan', {})
    output_config = config.get('output', {})

    directory = scan_config.get('directory', './')
    file_extensions = scan_config.get('file_extensions', ['.py'])
    supported_languages = scan_config.get('supported_languages', ['python'])
    batch_size_chars = scan_config.get('batch_size_chars', 4000)
    max_concurrent = scan_config.get('max_concurrent', 5)
    results_file = output_config.get('results_file', 'scan_results.json')

    # Initialize CodeChunker
    chunker = CodeChunker(supported_languages)

    # Process and scan the codebase asynchronously
    results = asyncio.run(process_and_scan_codebase_batched(chunker, directory, file_extensions,
                                                            batch_size_chars=batch_size_chars,
                                                            max_concurrent=max_concurrent))
    # Save the results
    save_results(results, results_file)
    logging.info(f"Scan results saved to {results_file}")

def compare_detection_results(old_results: List[Dict], new_results: List[Dict]) -> List[Dict]:
    """
    Compares two sets of detection results and returns the differences.
    This example matches functions based on file path and start_line.
    """
    diff_results = []
    old_dict = {}
    for res in old_results:
        for func in res['functions']:
            key = (func['file_path'], func['start_line'])
            old_dict[key] = res.get('vulnerabilities', [])

    for res in new_results:
        for func in res['functions']:
            key = (func['file_path'], func['start_line'])
            old_vulns = old_dict.get(key, [])
            new_vulns = res.get('vulnerabilities', [])
            added = [v for v in new_vulns if v not in old_vulns]
            removed = [v for v in old_vulns if v not in new_vulns]
            diff_results.append({
                'file_path': func['file_path'],
                'start_line': func['start_line'],
                'diff': {'added': added, 'removed': removed}
            })
    return diff_results

def main():
    # Set up logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')

    # Parse command-line arguments
    parser_arg = argparse.ArgumentParser(description="Code Vulnerability Scanner")
    parser_arg.add_argument("--config", type=str, default="config.yaml", help="Path to configuration file")
    # parser_arg.add_argument("--exclude-dirs", type=str, nargs='*', default=[], help="Directories to exclude from scanning")
    args = parser_arg.parse_args()

    # Load configuration
    config = load_config(args.config)
    scan_config = config.get('scan', {})
    output_config = config.get('output', {})

    directory = scan_config.get('directory', './your_codebase')
    file_extensions = scan_config.get('file_extensions', ['.py'])
    exclude_dirs = scan_config.get('exclude_dirs', [])

    supported_languages = scan_config.get('supported_languages', ['python'])
    batch_size_chars = scan_config.get('batch_size_chars', 4000)
    max_concurrent = scan_config.get('max_concurrent', 5)
    results_file = output_config.get('results_file', 'scan_results.json')

    # Initialize CodeChunker
    chunker = CodeChunker(supported_languages)

    # Process and scan the codebase asynchronously
    results = asyncio.run(process_and_scan_codebase_batched(chunker,
                                                            directory,
                                                            file_extensions,
                                                            exclude_dirs,
                                                            max_concurrent=max_concurrent))


    # # Save the results
    # final_result = []
    # validator = HighRiskValidator()
    #
    # for result in results:
    #     if result['vulnerabilities']['is_vulnerability']:
    #         validated = validator.validate(result)
    #         final_result.append(validated)

    save_results(results, results_file)
    logging.info(f"Scan results saved to {results_file}")

if __name__ == "__main__":

    main()


