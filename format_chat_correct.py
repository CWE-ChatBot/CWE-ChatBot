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
    
    # Split by the marker pattern (B\nBMAD full stack\nCustom Gem\nShow thinking)
    # Note: the spaces at the end of each line are preserved
    parts = content.split("B  \nBMAD full stack  \nCustom Gem  \nShow thinking\n")
    
    formatted_parts = []
    
    for i, part in enumerate(parts):
        part = part.strip()
        if not part:
            continue
            
        if i == 0:
            # First part contains title and first user input
            lines = part.split('\n')
            # Find where the actual conversation starts (after the title)
            start_idx = 0
            for j, line in enumerate(lines):
                if line.strip() and not line.startswith('#'):
                    start_idx = j
                    break
            
            if start_idx < len(lines):
                user_content = '\n'.join(lines[start_idx:]).strip()
                if user_content:
                    formatted_parts.append(f"> **USER:** {user_content}")
        else:
            # All other parts alternate: LLM response, then user input (if any)
            # Split each part to separate LLM response from next user input
            
            # Look for patterns that indicate user input within this section
            lines = part.split('\n')
            llm_lines = []
            user_lines = []
            found_user_input = False
            
            for j, line in enumerate(lines):
                # User input is typically bold and short, or specific responses
                if (not found_user_input and 
                    line.strip() and
                    (line.startswith('**') and line.endswith('**') and len(line) < 200) or
                    line.strip() in ['Interactive Mode', 'YOLO Mode', '9', '10', 'yes', 'no'] or
                    (line.startswith('**') and 'mode' in line.lower())):
                    found_user_input = True
                    user_lines = lines[j:]
                    llm_lines = lines[:j]
                    break
            
            if not found_user_input:
                llm_lines = lines
            
            # Add LLM response
            llm_content = '\n'.join(llm_lines).strip()
            if llm_content:
                formatted_parts.append(f"**LLM:** {llm_content}")
            
            # Add user input if found
            if user_lines:
                user_content = '\n'.join(user_lines).strip()
                if user_content:
                    formatted_parts.append(f"> **USER:** {user_content}")
    
    # Create final formatted content
    formatted_content = "# BMAD Planning Chat - Formatted\n\n" + "\n\n".join(formatted_parts)
    
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