#!/usr/bin/env python3
"""
Script to update chat formatting to use GitHub admonitions for user input
"""

import re

def update_chat_formatting(input_file, output_file):
    with open(input_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Pattern to match user input lines
    user_pattern = r'> \*\*USER:\*\* (.+?)(?=\n\n|\n\*\*LLM|$)'
    
    def replace_user_input(match):
        user_text = match.group(1).strip()
        # Remove any extra ** formatting from the user text
        user_text = user_text.replace('**', '')
        return f'> [!IMPORTANT] **User**\n> {user_text}'
    
    # Replace all user input patterns
    updated_content = re.sub(user_pattern, replace_user_input, content, flags=re.DOTALL)
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(updated_content)

if __name__ == "__main__":
    update_chat_formatting('docs/bmad_planning_chat_manual.md', 'docs/bmad_planning_chat_admonitions.md')
    print("Updated chat formatting with GitHub admonitions!")