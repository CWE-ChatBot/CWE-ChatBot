#!/usr/bin/env python3
"""
Script to properly format BMad user stories chat by separating user input from LLM responses
"""

import re

def format_user_stories_chat(input_file, output_file):
    with open(input_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Find all BMad marker positions
    bmad_pattern = r'B\s*\nBMAD.*?\nShow thinking\s*\n'
    markers = list(re.finditer(bmad_pattern, content, flags=re.MULTILINE | re.DOTALL))
    
    formatted_lines = []
    formatted_lines.append("# BMad User Stories Chat - Formatted")
    formatted_lines.append("")
    formatted_lines.append("## Formatting Guide")
    formatted_lines.append("- User inputs are highlighted with GitHub admonitions")
    formatted_lines.append("- LLM responses show agent context and content")
    formatted_lines.append("- BMad interface markers removed for clarity")
    formatted_lines.append("")
    formatted_lines.append("---")
    formatted_lines.append("")
    
    # Process the first section (before first BMad marker)
    if markers:
        first_section = content[:markers[0].start()].strip()
        if first_section:
            formatted_lines.append("## Initial User Request")
            formatted_lines.append("")
            formatted_lines.append(first_section)
            formatted_lines.append("")
    
    # Process each BMad agent section
    for i, marker in enumerate(markers):
        # Get the content after this marker
        start_pos = marker.end()
        end_pos = markers[i + 1].start() if i + 1 < len(markers) else len(content)
        section_content = content[start_pos:end_pos].strip()
        
        if not section_content:
            continue
        
        # Look for user input at the end of this section
        lines = section_content.split('\n')
        user_input = None
        agent_content = section_content
        
        # Check the last few lines for user input
        for j in range(len(lines) - 1, max(len(lines) - 5, 0), -1):
            line = lines[j].strip()
            # Common user responses
            if line in ['yes', 'no'] or (len(line) < 150 and any(word in line.lower() for word in ['yes', 'proceed', 'continue', 'expand', 'update', 'can you'])):
                user_input = line
                # Remove user input from agent content
                agent_content = '\n'.join(lines[:j]).strip()
                break
        
        # Determine agent type based on content
        agent_type = "BMad Agent"
        if "Security Agent" in agent_content or "Chris" in agent_content:
            agent_type = "BMad Security Agent (Chris)"
        elif "Product Manager" in agent_content or "John" in agent_content:
            agent_type = "BMad Product Manager (John)"
        
        # Add agent response
        formatted_lines.append(f"## {agent_type}")
        formatted_lines.append("")
        formatted_lines.append(agent_content)
        formatted_lines.append("")
        
        # Add user input if found
        if user_input:
            formatted_lines.append(f"> [!IMPORTANT] **User Input**")
            formatted_lines.append(f"> {user_input}")
            formatted_lines.append("")

    # Write the formatted content
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write('\n'.join(formatted_lines))

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        input_file = sys.argv[1]
        output_file = sys.argv[2] if len(sys.argv) > 2 else input_file.replace('.md', '_formatted_final.md')
    else:
        input_file = 'docs/chats/bmad_user_stories.md'
        output_file = 'docs/chats/bmad_user_stories_formatted_final.md'
    
    format_user_stories_chat(input_file, output_file)
    print(f"Chat formatting complete! Output: {output_file}")