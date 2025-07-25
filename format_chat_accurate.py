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
        lines = f.readlines()
    
    formatted_sections = []
    current_section = []
    section_type = None  # 'user' or 'llm'
    
    i = 0
    while i < len(lines):
        line = lines[i].rstrip('\n')
        
        # Check if we hit the marker pattern
        if (line == "B  " and 
            i + 1 < len(lines) and lines[i + 1].rstrip('\n') == "BMAD full stack  " and
            i + 2 < len(lines) and lines[i + 2].rstrip('\n') == "Custom Gem  " and
            i + 3 < len(lines) and lines[i + 3].rstrip('\n') == "Show thinking"):
            
            # Process the current section (this is user input before the marker)
            if current_section:
                section_content = '\n'.join(current_section).strip()
                if section_content and not section_content.startswith('# **Conversation with Gemini**'):
                    formatted_sections.append(f"> **USER:** {section_content}")
                current_section = []
            
            # Skip the 4 marker lines and any blank line that follows
            i += 4
            if i < len(lines) and lines[i].strip() == "":
                i += 1
            
            section_type = 'llm'
            continue
        
        # If we're in an LLM section and encounter what looks like user input
        # (usually starts with specific patterns or is short responses)
        if (section_type == 'llm' and 
            line.strip() and 
            not line.startswith(('Alright', 'Got it', 'Excellent', 'Perfect', 'Great', 'Thank you', 'Okay', 
                               'Now', 'Let', 'Here', 'The', 'This', 'I', 'We', 'You', 'Based', 'From', 
                               '*', '**', '#', '-', '1.', '2.', '3.', '4.', '5.', '6.', '7.', '8.', '9.')) and
            len(line.strip()) < 200 and  # Short responses are usually user input
            not line.strip().endswith('.') and
            not line.strip().endswith(':') and
            ('**' in line or line.startswith(('yes', 'no', 'Interactive', 'YOLO', '9', '10')))):
            
            # Process the current LLM section
            if current_section:
                section_content = '\n'.join(current_section).strip()
                if section_content:
                    formatted_sections.append(f"**LLM:** {section_content}")
                current_section = []
            
            section_type = 'user'
        
        current_section.append(line)
        i += 1
    
    # Process any remaining section
    if current_section:
        section_content = '\n'.join(current_section).strip()
        if section_content:
            if section_type == 'llm':
                formatted_sections.append(f"**LLM:** {section_content}")
            else:
                formatted_sections.append(f"> **USER:** {section_content}")
    
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