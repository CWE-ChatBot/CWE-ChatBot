# GitHub User Story Workflow

A Kanban board (standard GitHub Project template) is used that has 5 columns
1. Backlog
2. Ready
3. In progress
4. In review
5. Done


## Add User Stories to GitHub Project

> [!IMPORTANT] **User Input**
> I want to add the stories in @docs/stories/ to this project https://github.com/orgs/CWE-ChatBot/projects/1

### GitHub CLI

● The GitHub CLI needs to be authenticated for this session. Since the interactive login is timing out, you'll need to authenticate it manually. Here are the options:

  1. Manual Authentication: Run gh auth login in your terminal outside of this Claude Code session and follow the prompts
  2. Token Authentication: If you have a GitHub personal access token, you can use gh auth login --with-token
  3. Browser Authentication: Use gh auth login --web in your terminal

● Bash(gh issue create --repo CWE-ChatBot/CWE-ChatBot --title "Epic 1.1: Project Repository Setup" --body-file docs/stories/1.1.Project-Repository-Setup.md)

● Great! Let me continue creating issues for all the user stories. I'll create them systematically:

● Bash(gh issue create --repo CWE-ChatBot/CWE-ChatBot --title "Epic 1.2: Basic Chainlit Application Deployment to Cloud Run" --body-file docs/stories/1.2.Chainlit-Depl…)

  All issues have been created with the full markdown content from their respective story files. You can now manually add them to the "Backlog" column in your project board at https://github.com/orgs/CWE-ChatBot/projects/1, or if you need help with
  that step, I can provide instructions for bulk adding them to the project board.

### GitHub Add Issues to Project

Method 1: Bulk Selection via GitHub Web Interface (Recommended)

  1. Go to https://github.com/CWE-ChatBot/CWE-ChatBot/issues
  2. Use the checkboxes to select issues #1-14
  3. Click the "Projects" dropdown in the bulk actions toolbar
  4. Select your "CWE ChatBot Development" project
  5. All selected issues will be added to the project board at once

### GitHub Add Issues to Backlog

Tickets are created with No Status so add them to the Backlog column.

### Create a plan and save the plan to the ticket

> [!IMPORTANT] **User Input**
> for ticket Epic 1.1, create a plan and save the plan to the ticket

The plan is saved
1. localling in docs/plans (for Claude Code to use)
2. in the ticket in Git (for persistent storage and review)

## Ready 

Manually review the ticket Plan and once ready, manually move it to Ready column.

> [!NOTE] 
> A ticket is made Ready just in time i.e. all tickets are not made ready at once. Instead the next ticket is made ready when the previous one is completed, so that the ticket is made ready with the latest information.

## In progress



Kickoff the user story implementation, manually move the ticket to In progress column.

When the functionality is successfully

- implemented - all tasks are completed
- tested 

the ticket is updated with the 

- test results 
- details on the files changed (relative to the last commit). 

The ticket is moved to In review column.

## In review

The ticket content is reviewed.
If AOK, then the ticket is manually moved to Done.

Notes
1. The transition of tickets on the board is deliberately manual as these are manual review points before and after the ticket is implemented.
2. The User Story has the Task list already (and other info).
3. The plan is saved on the ticket (as a comment) as it provides useful detail for pre/post implementation review.
4. Claude Code commands for git are not used or created or necessary (for what I wanted).


