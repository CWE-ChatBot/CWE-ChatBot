#!/usr/bin/env python3
"""
Precise script to format BMad planning chat with exact pattern matching
"""

import re

def format_chat(input_file, output_file):
    with open(input_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Remove the initial header
    content = re.sub(r'^# \*\*Conversation with Gemini\*\*\n\n', '', content)
    
    # The exact pattern from the file
    marker_pattern = r'B\s+\nBMAD full stack\s+\nCustom Gem\s+\nShow thinking\n*'
    
    # Split by this exact pattern
    parts = re.split(marker_pattern, content)
    
    # Initialize output
    result = []
    result.append("# BMad Planning Chat - User vs LLM Formatted\n")
    result.append("## Formatting Guide")
    result.append("- **USER INPUT**: Highlighted with `> ` prefix")
    result.append("- **LLM RESPONSE**: Regular text with agent context clearly marked")
    result.append("- **CLEAN FORMAT**: BMad interface markers removed for clarity\n")
    result.append("---\n")
    
    # Process each part
    for i, part in enumerate(parts):
        part = part.strip()
        if not part:
            continue
            
        if i == 0:
            # First part is always user input
            if part:
                result.append(f"> **USER:** {part}\n")
        else:
            # Determine agent type from content
            agent_type = "BMAD Agent"
            if "Business Analyst" in part or "Mary, the Business Analyst" in part:
                agent_type = "BMAD Analyst"
            elif "transforming into" in part.lower() and "architect" in part.lower():
                agent_type = "BMAD Architect"
            elif "PM" in part and ("Product Manager" in part or "transforming" in part.lower()):
                agent_type = "BMAD PM Agent"
            elif "Developer" in part:
                agent_type = "BMAD Developer"
            elif "QA" in part:
                agent_type = "BMAD QA Agent"
            
            # Add the LLM response
            result.append(f"**LLM ({agent_type}):**\n")
            result.append(f"{part}\n")
    
    # Write output
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write('\n'.join(result))

if __name__ == "__main__":
    format_chat('docs/bmad_planning_chat.md', 'docs/bmad_planning_chat_final.md')
    print("Precise formatting complete!")