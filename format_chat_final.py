#!/usr/bin/env python3
"""
Script to properly format the BMAD planning chat by:
1. Removing the BMAD markers completely
2. Adding clear prefixes for user input and LLM responses
3. Preserving all original formatting and line breaks
"""

import re

def format_chat_file(input_file, output_file):
    with open(input_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # The marker pattern consists of these 4 lines:
    # B  
    # BMAD full stack  
    # Custom Gem  
    # Show thinking
    # (with trailing spaces and followed by an empty line)
    
    marker_pattern = r'B  \nBMAD full stack  \nCustom Gem  \nShow thinking\n(?:\n)?'
    
    # Split content by the marker pattern
    sections = re.split(marker_pattern, content)
    
    formatted_sections = []
    
    for i, section in enumerate(sections):
        section = section.strip()
        if not section:
            continue
            
        if i == 0:
            # First section is user input (before any markers)
            # Remove the title and start with the actual first user input
            lines = section.split('\n')
            # Skip the title line and find the first actual user input
            start_idx = 0
            for j, line in enumerate(lines):
                if line.strip() and not line.startswith('#'):
                    start_idx = j
                    break
            
            user_content = '\n'.join(lines[start_idx:]).strip()
            if user_content:
                formatted_sections.append(f"> **USER:** {user_content}")
        elif i % 2 == 1:
            # Odd numbered sections (after markers) are LLM responses
            if section:
                formatted_sections.append(f"**LLM:** {section}")
        else:
            # Even numbered sections (between LLM response and next marker) are user input
            if section:
                formatted_sections.append(f"> **USER:** {section}")
    
    # Join sections with double newlines for clear separation
    formatted_content = "# BMAD Planning Chat - Formatted\n\n" + "\n\n".join(formatted_sections)
    
    # Write the formatted content
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(formatted_content)

if __name__ == "__main__":
    input_file = "/home/chris/work/CyberSecAI/cwe_chatbot_bmad/docs/bmad_planning_chat.md"
    output_file = "/home/chris/work/CyberSecAI/cwe_chatbot_bmad/docs/bmad_planning_chat_formatted_complete.md"
    
    format_chat_file(input_file, output_file)
    print(f"Formatted chat file created: {output_file}")
    
    # Show some stats
    with open(output_file, 'r') as f:
        lines = len(f.readlines())
    print(f"Output file has {lines} lines")
    
    # Count sections
    with open(output_file, 'r') as f:
        content = f.read()
        user_sections = content.count("> **USER:**")
        llm_sections = content.count("**LLM:**")
    print(f"Found {user_sections} user sections and {llm_sections} LLM sections")