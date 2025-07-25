#!/usr/bin/env python3
"""
Final script to properly format the BMAD planning chat.
This manually processes each section to ensure accuracy.
"""

def format_chat_file(input_file, output_file):
    with open(input_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # The marker is exactly these 4 lines (with trailing spaces):
    marker = "B  \nBMAD full stack  \nCustom Gem  \nShow thinking\n"
    
    # Split content by marker
    sections = content.split(marker)
    
    result = ["# BMAD Planning Chat - Formatted\n"]
    
    for i, section in enumerate(sections):
        # Remove leading/trailing whitespace but preserve internal formatting
        section = section.strip()
        if not section:
            continue
            
        if i == 0:
            # First section: title + first user input
            lines = section.split('\n')
            # Skip the conversation title
            content_lines = []
            skip_title = True
            for line in lines:
                if skip_title and line.startswith('#'):
                    continue
                skip_title = False
                content_lines.append(line)
            
            user_content = '\n'.join(content_lines).strip()
            if user_content:
                result.append(f"> **USER:** {user_content}\n")
        else:
            # Every section after a marker is an LLM response
            # But it might also contain the next user input at the end
            
            # Split the section to find where user input might start
            lines = section.split('\n')
            llm_end = len(lines)
            
            # Look for user input from the end backwards
            # User input is typically:
            # - Bold text in ** **
            # - Short responses like "Interactive Mode", "9", etc.
            # - Questions or commands
            for j in range(len(lines) - 1, -1, -1):
                line = lines[j].strip()
                if not line:
                    continue
                    
                # Check if this looks like user input
                if (line.startswith('**') and line.endswith('**') and len(line) < 200 and 
                    ('mode' in line.lower() or 'create' in line.lower() or 
                     any(word in line.lower() for word in ['yes', 'no', 'interactive', 'yolo']))):
                    # This is likely user input - find where it starts
                    for k in range(j, -1, -1):
                        if lines[k].strip() and not lines[k].startswith('**'):
                            llm_end = k + 1
                            break
                    else:
                        llm_end = j
                    break
                elif line in ['Interactive Mode', 'YOLO Mode', '9', '10', 'yes', 'no']:
                    llm_end = j
                    break
            
            # Extract LLM response
            llm_lines = lines[:llm_end]
            llm_content = '\n'.join(llm_lines).strip()
            if llm_content:
                result.append(f"**LLM:** {llm_content}\n")
            
            # Extract user input if present
            if llm_end < len(lines):
                user_lines = lines[llm_end:]
                user_content = '\n'.join(user_lines).strip()
                if user_content:
                    result.append(f"> **USER:** {user_content}\n")
    
    # Write the result
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write('\n'.join(result))

if __name__ == "__main__":
    input_file = "/home/chris/work/CyberSecAI/cwe_chatbot_bmad/docs/bmad_planning_chat.md"
    output_file = "/home/chris/work/CyberSecAI/cwe_chatbot_bmad/docs/bmad_planning_chat_formatted_complete.md"
    
    format_chat_file(input_file, output_file)
    print(f"Formatted chat file created: {output_file}")
    
    # Show some stats
    with open(output_file, 'r') as f:
        content = f.read()
        lines = len(content.split('\n'))
        user_sections = content.count("> **USER:**")
        llm_sections = content.count("**LLM:**")
    
    print(f"Output file has {lines} lines")
    print(f"Found {user_sections} user sections and {llm_sections} LLM sections")