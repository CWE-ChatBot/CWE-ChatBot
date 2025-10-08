#!/usr/bin/env python3
"""
Script to properly format the BMAD planning chat by:
1. Removing the BMAD markers completely
2. Adding clear prefixes for user input and LLM responses
3. Preserving all original formatting and line breaks
"""


def format_chat_file(input_file, output_file):
    with open(input_file, "r", encoding="utf-8") as f:
        lines = f.readlines()

    formatted_lines = []
    current_section = []
    is_user_input = True  # Start assuming user input
    i = 0

    while i < len(lines):
        line = lines[i].rstrip("\n")

        # Check if this is the start of BMAD markers
        if (
            line == "B"
            and i + 1 < len(lines)
            and lines[i + 1].strip() == "BMAD full stack"
            and i + 2 < len(lines)
            and lines[i + 2].strip() == "Custom Gem"
            and i + 3 < len(lines)
            and lines[i + 3].strip() == "Show thinking"
        ):
            # Process the current section before the markers
            if current_section:
                if is_user_input:
                    # Add user prefix to the first non-empty line
                    section_text = "\n".join(current_section)
                    if section_text.strip():
                        formatted_lines.append(f"> **USER:** {section_text}")
                else:
                    # Add LLM prefix to the first non-empty line
                    section_text = "\n".join(current_section)
                    if section_text.strip():
                        formatted_lines.append(f"**LLM:** {section_text}")

                formatted_lines.append("")  # Add blank line between sections
                current_section = []

            # Skip the 4 marker lines and any following empty line
            i += 4
            if i < len(lines) and lines[i].strip() == "":
                i += 1

            # Switch to LLM response mode
            is_user_input = False
            continue

        # Check if we're starting a new user input section
        # This happens when we encounter text after an LLM response that doesn't start with typical LLM indicators
        if (
            not is_user_input
            and line.strip()
            and not line.startswith(("**", "*", "#", "-", "1.", "2.", "3.", "4.", "5."))
            and not line.startswith(
                (
                    "Alright",
                    "Got it",
                    "Excellent",
                    "Perfect",
                    "Great",
                    "Thank you",
                    "Okay",
                )
            )
        ):
            # Process the current LLM section
            if current_section:
                section_text = "\n".join(current_section)
                if section_text.strip():
                    formatted_lines.append(f"**LLM:** {section_text}")
                formatted_lines.append("")  # Add blank line between sections
                current_section = []

            is_user_input = True

        current_section.append(line)
        i += 1

    # Process any remaining section
    if current_section:
        section_text = "\n".join(current_section)
        if section_text.strip():
            if is_user_input:
                formatted_lines.append(f"> **USER:** {section_text}")
            else:
                formatted_lines.append(f"**LLM:** {section_text}")

    # Write the formatted content
    with open(output_file, "w", encoding="utf-8") as f:
        f.write("\n".join(formatted_lines))


if __name__ == "__main__":
    input_file = (
        "/home/chris/work/CyberSecAI/cwe_chatbot_bmad/docs/bmad_planning_chat.md"
    )
    output_file = "/home/chris/work/CyberSecAI/cwe_chatbot_bmad/docs/bmad_planning_chat_formatted_fixed.md"

    format_chat_file(input_file, output_file)
    print(f"Formatted chat file created: {output_file}")
