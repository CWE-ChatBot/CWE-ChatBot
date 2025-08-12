#!/usr/bin/env python3
"""
Script to properly format BMad planning chat by separating user input from LLM responses
while preserving all original formatting and line breaks
"""

import re
import sys

def format_chat(input_file, output_file):
    with open(input_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Remove the initial header if it exists
    content = re.sub(r'^# \*\*Conversation with Gemini\*\*\n\n', '', content)
    
    formatted_lines = []
    formatted_lines.append("# BMad Planning Chat - User vs LLM Formatted")
    formatted_lines.append("")
    formatted_lines.append("## Formatting Guide")
    formatted_lines.append("- **USER INPUT**: Highlighted with GitHub admonitions `> [!IMPORTANT] \"User\"`")
    formatted_lines.append("- **LLM RESPONSE**: Regular text with agent context clearly marked")
    formatted_lines.append("- **CLEAN FORMAT**: BMad interface markers removed for clarity")
    formatted_lines.append("")
    formatted_lines.append("---")
    formatted_lines.append("")
    
    # Use a simpler approach: split by the BMad header pattern and process alternating sections
    # Pattern includes the full BMad sequence
    full_marker_pattern = r'B\s*\nBMAD fullstack Security v2\s*\nCustom Gem\s*\nShow thinking\s*\n'
    
    # Split content by this pattern
    parts = re.split(full_marker_pattern, content)
    
    # The first part is always user input
    # Subsequent parts alternate: LLM response, user input, LLM response, user input, etc.
    
    for i, part in enumerate(parts):
        part = part.strip()
        if not part:
            continue
            
        if i == 0:
            # First part is always user input
            formatted_lines.append("> [!IMPORTANT] **User**")
            formatted_lines.append(f"> {part}")
            formatted_lines.append("")
        elif i % 2 == 1:
            # Odd indices are LLM responses (after BMad markers)
            # Determine agent type
            agent_type = "BMAD Agent"
            if "UX Expert" in part or "Sally" in part:
                agent_type = "BMAD UX Expert"
            elif "Business Analyst" in part or "Mary" in part:
                agent_type = "BMAD Analyst"
            elif "Product Manager" in part and "PM" in part:
                agent_type = "BMAD PM Agent"
            elif "Architect" in part:
                agent_type = "BMAD Architect"
            elif "Developer" in part:
                agent_type = "BMAD Developer"
            elif "QA" in part:
                agent_type = "BMAD QA Agent"
            
            # Check if this part contains user input at the end
            # Look for content after extensive whitespace that could be user input
            lines = part.split('\n')
            
            # Find potential user input at the end
            llm_content = []
            user_input = []
            
            # Look for a pattern where there's content, then lots of empty lines, then more content
            found_break = False
            empty_line_count = 0
            
            for j, line in enumerate(lines):
                if not line.strip():
                    empty_line_count += 1
                else:
                    if empty_line_count >= 4 and llm_content and not found_break:
                        # This might be the start of user input
                        found_break = True
                        user_input.append(line)
                    elif found_break:
                        user_input.append(line)
                    else:
                        # Reset empty line count and continue with LLM content
                        llm_content.extend([''] * empty_line_count)
                        llm_content.append(line)
                    empty_line_count = 0
            
            # Output LLM response
            formatted_lines.append(f"**LLM ({agent_type}):**")
            formatted_lines.append("")
            formatted_lines.append('\n'.join(llm_content).strip())
            formatted_lines.append("")
            
            # Output user input if found
            if user_input and any(line.strip() for line in user_input):
                user_text = '\n'.join(user_input).strip()
                formatted_lines.append("> [!IMPORTANT] **User**")
                formatted_lines.append(f"> {user_text}")
                formatted_lines.append("")
            
        else:
            # Even indices (after first) should be LLM responses (parts after splits)
            # These are LLM responses that come after user inputs embedded in previous parts
            
            # Determine agent type
            agent_type = "BMAD Agent" 
            if "UX Expert" in part or "Sally" in part:
                agent_type = "BMAD UX Expert"
            elif "Business Analyst" in part or "Mary" in part:
                agent_type = "BMAD Analyst"
            elif "Product Manager" in part and "PM" in part:
                agent_type = "BMAD PM Agent"
            elif "Architect" in part:
                agent_type = "BMAD Architect"
            elif "Developer" in part:
                agent_type = "BMAD Developer"
            elif "QA" in part:
                agent_type = "BMAD QA Agent"
            
            formatted_lines.append(f"**LLM ({agent_type}):**")
            formatted_lines.append("")
            formatted_lines.append(part)
            formatted_lines.append("")
    
    # Write the formatted content
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write('\n'.join(formatted_lines))

if __name__ == "__main__":
    import sys
    import os
    
    if len(sys.argv) != 2:
        print("Usage: python3 process_chat_final.py <input_file>")
        print("Example: python3 process_chat_final.py docs/chats/my_chat.md")
        sys.exit(1)
    
    input_file = sys.argv[1]
    
    # Check if input file exists
    if not os.path.exists(input_file):
        print(f"Error: Input file '{input_file}' not found.")
        sys.exit(1)
    
    # Generate output filename by inserting "_formatted" before the extension
    file_path, file_ext = os.path.splitext(input_file)
    output_file = f"{file_path}_formatted{file_ext}"
    
    print(f"Processing: {input_file}")
    print(f"Output: {output_file}")
    
    format_chat(input_file, output_file)
    print("Chat formatting complete!")