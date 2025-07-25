#!/usr/bin/env python3
"""
Script to properly format the BMAD planning chat by:
1. Removing the BMAD markers completely
2. Adding clear prefixes for user input and LLM responses
3. Preserving all original formatting and line breaks
"""

def format_chat_file(input_file, output_file):
    with open(input_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Split content by the BMAD marker pattern
    # The pattern is: B\nBMAD full stack\nCustom Gem\nShow thinking\n
    marker_pattern = "B  \nBMAD full stack  \nCustom Gem  \nShow thinking\n"
    
    sections = content.split(marker_pattern)
    
    formatted_sections = []
    
    for i, section in enumerate(sections):
        section = section.strip()
        if not section:
            continue
            
        if i == 0:
            # First section is user input (before any markers)
            if section:
                formatted_sections.append(f"> **USER:** {section}")
        elif i % 2 == 1:
            # Odd numbered sections (after markers) are LLM responses
            if section:
                formatted_sections.append(f"**LLM:** {section}")
        else:
            # Even numbered sections (between LLM response and next marker) are user input
            if section:
                formatted_sections.append(f"> **USER:** {section}")
    
    # Join sections with double newlines for clear separation
    formatted_content = "\n\n".join(formatted_sections)
    
    # Write the formatted content
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(formatted_content)

if __name__ == "__main__":
    input_file = "/home/chris/work/CyberSecAI/cwe_chatbot_bmad/docs/bmad_planning_chat.md"
    output_file = "/home/chris/work/CyberSecAI/cwe_chatbot_bmad/docs/bmad_planning_chat_formatted_fixed.md"
    
    format_chat_file(input_file, output_file)
    print(f"Formatted chat file created: {output_file}")