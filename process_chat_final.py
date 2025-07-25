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
    
    # Split content by the BMad markers - more flexible pattern
    marker_pattern = r'B\s*\n*BMAD full stack\s*\n*Custom Gem\s*\n*Show thinking\s*\n*-*\s*\n*'
    
    # Split the content
    parts = re.split(marker_pattern, content, flags=re.MULTILINE)
    
    formatted_lines = []
    formatted_lines.append("# BMad Planning Chat - User vs LLM Formatted")
    formatted_lines.append("")
    formatted_lines.append("## Formatting Guide")
    formatted_lines.append("- **USER INPUT**: Highlighted with `> ` prefix")
    formatted_lines.append("- **LLM RESPONSE**: Regular text with agent context clearly marked")
    formatted_lines.append("- **CLEAN FORMAT**: BMad interface markers removed for clarity")
    formatted_lines.append("")
    formatted_lines.append("---")
    formatted_lines.append("")
    
    for i, part in enumerate(parts):
        part = part.strip()
        if not part:
            continue
            
        if i == 0:
            # First part is user input
            if part:
                formatted_lines.append(f"> **USER:** {part}")
                formatted_lines.append("")
        else:
            # This is an LLM response - determine agent type
            agent_type = "BMAD Agent"
            if "Business Analyst" in part or "Mary, the Business Analyst" in part:
                agent_type = "BMAD Analyst"
            elif "Product Manager" in part and "PM" in part:
                agent_type = "BMAD PM Agent"  
            elif "Architect" in part:
                agent_type = "BMAD Architect"
            elif "Developer" in part:
                agent_type = "BMAD Developer"
            elif "QA" in part:
                agent_type = "BMAD QA Agent"
            
            # Add LLM response with preserved formatting
            formatted_lines.append(f"**LLM ({agent_type}):**")
            formatted_lines.append("")
            formatted_lines.append(part)
            formatted_lines.append("")
            
            # Look for user input at the end - simple heuristic
            # If the next part exists, there should be user input
            if i < len(parts) - 1:
                # Find potential user input at the end of this section
                lines = part.split('\n')
                
                # Look for short lines that might be user commands
                potential_user_input = []
                for j in range(len(lines) - 1, max(len(lines) - 10, 0), -1):
                    line = lines[j].strip()
                    if line and len(line) < 50 and not line.startswith('*') and not line.startswith('#'):
                        if any(word in line.lower() for word in ['yes', 'no', 'interactive', 'yolo', 'mode', '9', '1', '2', '3', '4', '5', '6', '7', '8']):
                            potential_user_input.insert(0, line)
                            break
                
                if potential_user_input:
                    # Remove the user input from the LLM response
                    user_text = potential_user_input[0]
                    # Update the LLM response to remove this line
                    part_without_user = part
                    if user_text in part_without_user:
                        last_occurrence = part_without_user.rfind(user_text)
                        part_without_user = part_without_user[:last_occurrence] + part_without_user[last_occurrence + len(user_text):]
                    
                    # Update the formatted response
                    formatted_lines[-2] = part_without_user.rstrip()
                    
                    # Add user input
                    formatted_lines.append(f"> **USER:** {user_text}")
                    formatted_lines.append("")
    
    # Write the formatted content
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write('\n'.join(formatted_lines))

if __name__ == "__main__":
    format_chat('docs/bmad_planning_chat.md', 'docs/bmad_planning_chat_properly_formatted.md')
    print("Chat formatting complete!")