import json
import subprocess
import logging
import tempfile
import os

from logging_config import setup_logging

# Set up logging
setup_logging()
logger = logging.getLogger(__name__)

def get_semgrep_config(language: str) -> str:
    """Returns the appropriate Semgrep configuration URL based on the language."""
    language_configs = {
        "python": "https://semgrep.dev/p/python",
        "javascript": "https://semgrep.dev/p/javascript",
        "typescript": "https://semgrep.dev/p/typescript",
        "java": "https://semgrep.dev/p/java",
        "go": "https://semgrep.dev/p/go",
        "ruby": "https://semgrep.dev/p/ruby",
        "php": "https://semgrep.dev/p/php",
        "c": "https://semgrep.dev/p/c",
        "cpp": "https://semgrep.dev/p/cpp",
        "csharp": "https://semgrep.dev/p/csharp",
        "objectivec": "https://semgrep.dev/p/objectivec",
        "swift": "https://semgrep.dev/p/swift",
        "kotlin": "https://semgrep.dev/p/kotlin",
        "bash": "https://semgrep.dev/p/shell",
        "dockerfile": "https://semgrep.dev/p/dockerfile",
        "yaml": "https://semgrep.dev/p/yaml",
        "json": "https://semgrep.dev/p/json",
        "terraform": "https://semgrep.dev/p/terraform",
        "markdown": "https://semgrep.dev/p/markdown",
        "rust": "https://semgrep.dev/p/rust",
        "hcl": "https://semgrep.dev/p/hcl",
        "scala": "https://semgrep.dev/p/scala"
    }
    return language_configs.get(language.lower(), "auto")

def run_semgrep(code: str, language: str):
    """Runs Semgrep dynamically based on the detected language."""
    semgrep_config = get_semgrep_config(language)
    logger.info(f"Running Semgrep with config: {semgrep_config} for language: {language}")

    with tempfile.NamedTemporaryFile(mode="w+", suffix=".txt", delete=False) as temp_file:
        temp_file.write(code)
        temp_file.flush()
        temp_file_path = temp_file.name

    semgrep_cmd = ["semgrep", "--config", semgrep_config, "--json", temp_file_path]

    try:
        result = subprocess.run(semgrep_cmd, capture_output=True, text=True, check=True)
        findings = json.loads(result.stdout)
        logger.info(f"Semgrep analysis complete. Found {len(findings.get('results', []))} issues.")
        return findings.get("results", [])
    except subprocess.CalledProcessError as e:
        logger.error(f"Semgrep error: {e.stderr}")
        logger.error(f"Semgrep output: {e.stdout}")
        return []
    except json.JSONDecodeError:
        logger.error("Semgrep output is not in expected JSON format.")
        return []
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        return []
    finally:
        try:
            os.remove(temp_file_path)
        except OSError as e:
            logger.warning(f"Failed to delete temporary file {temp_file_path}: {e}")
