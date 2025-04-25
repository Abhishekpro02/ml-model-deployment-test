from tree_sitter_language_pack import get_parser, get_language
import os
import hashlib
from typing import List, Dict, Optional
import logging
class CodeChunker:
    def __init__(self, languages: List[str]):
        self.language_parsers = {}
        for lang in languages:
            try:
                parser = get_parser(lang)
                if parser is None:
                    raise ValueError(f"Parser not available for language: {lang}")
                self.language_parsers[lang] = parser
            except Exception as e:
                logging.warning(f"Failed to initialize parser for {lang}: {e}")

    def detect_language(self, file_name: str) -> str:
        extension_map = {
            '.py': 'python', '.js': 'javascript', '.java': 'java', '.cpp': 'cpp', '.c': 'c', '.go': 'go',
            '.rb': 'ruby', '.php': 'php', '.html': 'html', '.css': 'css', '.ts': 'typescript', '.tsx': 'typescript',
            '.jsx': 'javascript', '.swift': 'swift', '.kt': 'kotlin', '.rs': 'rust', '.scala': 'scala',
            '.sh': 'bash', '.pl': 'perl', '.r': 'r', '.sql': 'sql', '.lua': 'lua', '.h': 'c',
        }
        ext = os.path.splitext(file_name)[1]
        return extension_map.get(ext, 'unknown')

    def extract_chunks(self, code: str, language_name: str, file_path: str) -> List[Dict]:
        try:
            parser = get_parser(language_name)
            tree = parser.parse(code.encode('utf-8'))
        except Exception as e:
            logging.error(f"Failed to parse code for {file_path}: {e}")
            return self.fallback_semantic_chunks(code, file_path, language_name)

        root_node = tree.root_node
        code_lines = code.split('\n')
        total_lines = root_node.end_point[0] + 1  # 1-based line count

        # Existing configuration and setup
        node_types_by_lang = {
            'python': ['function_definition', 'class_definition', 'lambda'],
            'javascript': [ 'method_definition', 'class_declaration', 'arrow_function', 'function_expression'],
            'java': ['method_declaration', 'class_declaration', 'field_declaration', 'interface_declaration'],
            'cpp': ['function_definition', 'class_specifier', 'declaration', 'struct_specifier', 'enum_specifier',
                    'namespace_definition', 'template_declaration', 'preproc_def', 'preproc_if', 'preproc_include',
                    'lambda_expression'],
            'c': ['function_definition', 'declaration', 'struct_specifier', 'enum_specifier', 'preproc_def'],
            'go': ['function_declaration', 'method_declaration', 'type_declaration', 'function_literal'],
            'php': ['function_definition', 'method_declaration', 'class_declaration'],
            'ruby': ['method', 'class'],
            'rust': ['function_item', 'struct_item', 'enum_item', 'trait_item', 'impl_item', 'mod_item',
                     'macro_definition', 'use_declaration', 'const_item', 'closure_expression']
        }

        target_node_types = set(node_types_by_lang.get(language_name, ['function_definition']))

        chunks = []
        seen_ranges = []
        code_bytes = code.encode('utf-8')

        # Existing helper functions
        def hash_chunk(text: str) -> str:
            return hashlib.sha256(text.encode('utf-8')).hexdigest()

        def is_overlapping(start: int, end: int) -> bool:
            for s, e in seen_ranges:
                if max(s, start) < min(e, end):
                    return True
            return False

        def is_trivial_function(node) -> bool:
            return (node.end_point[0] - node.start_point[0]) < 2

        # Modified traversal function
        def traverse(node, parent_type=None):
            if node.type in target_node_types:
                start_byte, end_byte = node.start_byte, node.end_byte
                if not is_overlapping(start_byte, end_byte):
                    chunk_text = code_bytes[start_byte:end_byte].decode('utf-8')

                    if language_name == 'javascript' and node.type == 'function_declaration':
                        # Ensure we capture all JS functions
                        chunks.append({
                            'type': 'func',
                            'code': chunk_text,
                            'start_line': node.start_point[0] + 1,
                            'end_line': node.end_point[0] + 1,
                            'file_path': file_path,
                            'lang': language_name,
                            'hash': hash_chunk(chunk_text)
                        })


                        seen_ranges.append((start_byte, end_byte))
                        return

                    if node.type == 'variable_declarator' and len(chunk_text.strip().splitlines()) < 2 and len(
                            chunk_text.strip()) < 30:
                        return

                    # if parent_type in target_node_types and is_trivial_function(node):
                    #     return

                    chunks.append({
                        'type': 'func',
                        'code': chunk_text,
                        'start_line': node.start_point[0] + 1,
                        'end_line': node.end_point[0] + 1,
                        'file_path': file_path,
                        'lang': language_name,
                        'hash': hash_chunk(chunk_text)
                    })
                    seen_ranges.append((start_byte, end_byte))
                    return

            for child in node.children:
                traverse(child, node.type)

        traverse(root_node)
        chunks.sort(key=lambda x: x['start_line'])

        # New code to capture non-function chunks
        non_function_chunks = []
        previous_end = 0

        for chunk in chunks:
            current_start = chunk['start_line']
            current_end = chunk['end_line']

            if current_start > previous_end + 1:
                gap_start = previous_end + 1
                gap_end = current_start - 1
                start_idx = gap_start - 1
                end_idx = gap_end

                if start_idx < len(code_lines):
                    if end_idx > len(code_lines):
                        end_idx = len(code_lines)
                    gap_lines = code_lines[start_idx:end_idx]
                    if gap_lines:
                        gap_code = '\n'.join(gap_lines)
                        if len(gap_code.strip())>0:
                            non_function_chunks.append({
                                'type': 'non_func',
                                'code': gap_code,
                                'start_line': gap_start,
                                'end_line': gap_end,
                                'file_path': file_path,
                                'lang': language_name,
                                'hash': hash_chunk(gap_code)
                            })

            previous_end = max(previous_end, current_end)

        # Handle remaining code after last chunk
        if previous_end < total_lines:
            gap_start = previous_end + 1
            gap_end = total_lines
            start_idx = gap_start - 1
            end_idx = gap_end

            if start_idx < len(code_lines):
                if end_idx > len(code_lines):
                    end_idx = len(code_lines)
                gap_lines = code_lines[start_idx:end_idx]
                if gap_lines:
                    gap_code = '\n'.join(gap_lines)

                    if len(gap_code.strip()) > 0:
                        non_function_chunks.append({
                            'type': 'non_func',
                            'code': gap_code,
                            'start_line': gap_start,
                            'end_line': gap_end,
                            'file_path': file_path,
                            'lang': language_name,
                            'hash': hash_chunk(gap_code)
                        })

        # Combine and sort all chunks
        all_chunks = chunks + non_function_chunks
        all_chunks.sort(key=lambda x: x['start_line'])

        return all_chunks



    def fallback_semantic_chunks(self, code: str, file_path: str, language_name: str) -> List[Dict]:
        lines = code.splitlines()
        chunks = []
        buffer = []
        current_start = 1

        thresholds_by_language = {
            'python': 40, 'javascript': 40, 'java': 50, 'cpp': 60, 'c': 60, 'go': 50,
            'php': 40, 'ruby': 30, 'html': 80, 'sql': 100
        }
        threshold_lines = thresholds_by_language.get(language_name, 50)

        indent_levels = []

        def flush_buffer():
            nonlocal buffer, current_start
            if buffer:
                chunk_text = "\n".join(buffer)
                chunks.append({
                    'function_code': chunk_text,
                    'start_line': current_start,
                    'end_line': current_start + len(buffer) - 1,
                    'file_path': file_path,
                    'lang': language_name,
                    'hash': hashlib.sha256(chunk_text.encode('utf-8')).hexdigest()
                })
                current_start += len(buffer)
                buffer.clear()
                indent_levels.clear()

        for i, line in enumerate(lines):
            stripped = line.strip()
            if not stripped:
                continue
            indent = len(line) - len(line.lstrip())
            indent_levels.append(indent)
            buffer.append(line)
            if len(buffer) >= threshold_lines or (len(indent_levels) >= 2 and indent_levels[-1] < indent_levels[-2]):
                flush_buffer()

        flush_buffer()
        return chunks

    def chunk_codebase(self, directory: str, file_extensions: List[str], exclude_dirs: Optional[List[str]] = None) -> List[Dict]:
        if exclude_dirs is None:
            exclude_dirs = []

        all_chunks = []
        for root, dirs, files in os.walk(directory):
            dirs[:] = [d for d in dirs if d not in exclude_dirs]

            for file in files:
                if any(file.endswith(ext) for ext in file_extensions):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            code = f.read()
                    except Exception as e:
                        logging.warning(f"Error reading {file_path}: {e}")
                        continue

                    language_name = self.detect_language(file)
                    if language_name == 'unknown':
                        logging.info(f"Skipping unknown language file: {file_path}")
                        continue

                    chunks = self.extract_chunks(code, language_name, file_path)
                    all_chunks.extend(chunks)

        return all_chunks

    def get_supported_languages(self) -> List[str]:
        return list(self.language_parsers.keys())

    def is_supported_file(self, file_name: str, file_extensions: List[str]) -> bool:
        return any(file_name.endswith(ext) for ext in file_extensions)

if __name__ == "__main__":
    supported_languages = ['python', 'javascript', 'java', 'cpp', 'c', 'go', 'ruby', 'php', 'html', 'css', 'rust']
    chunker = CodeChunker(supported_languages)

    # Specify the directory and list of file extensions to process.
    directory = "./data/"  # Update this to your codebase directory
    file_extensions = [".c"]  # Process both Python and JavaScript files, for example

    all_chunks = chunker.chunk_codebase(directory, file_extensions)

    for chunk_info in all_chunks:

            # Optionally, print chunk information for debugging
        print(f"File: {chunk_info['file_path']}")
        print(f"Code starts at line {chunk_info['start_line']} and ends at line {chunk_info['end_line']}")
        print(f"Code chunk: {chunk_info['type']}")
        print(chunk_info['code'])
        print("-" * 40)


