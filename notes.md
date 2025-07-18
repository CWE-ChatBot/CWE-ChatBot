# Notes

Gemini 2.5 Flash was used
GEM


Ref: https://github.com/bmadcode/BMAD-METHOD/blob/main/docs/bmad-workflow-guide.md


Add costs

## project brief

docs/project-brief.md


1. Create a Gemini GEM by copying this text into the GEM as instructions https://github.com/bmadcode/BMAD-METHOD/blob/main/dist/teams/team-fullstack.txt
2. > pm create-doc prd
3. > please provide the complete generated Project Brief for the CWE ChatBot
4. save as docs/project-brief.md
5. Manually review and edit
https://gemini.google.com/gem/c29107c278ed/995e343ba3538482

docs/project-brief.md

## PrD
Product Manager, please start in 'PRD Generation Mode', review the brief thoroughly to work with the user to create the PRD section by section as the template indicates, asking for any necessary clarification or suggesting improvements.

> proceed with executing the PM Requirements Checklist against the entire document to provide a final validation report


## Architecture

> *agent architect


## UI

attached is the current cwe cve color scheme so we should use that 



mermaid
( and " are not allowed in mermaid diagram text between ""


---

**I am now exiting my role as the Architect.**

You have a complete and approved Architecture Document. The next step is to activate the **Product Owner** to validate all project artifacts, prepare for sharding, and begin the story creation process for development.

You can activate the Product Owner using: `*agent po`
Then, you would prompt them to validate the artifacts: `*execute-checklist po-master-checklist`

Let me know how you'd like to proceed!


## PO

---

**I am now exiting my role as the Product Owner.**

You have successfully navigated the planning and design phases. All major project artifacts are approved. The team is now ready to begin the **Development Phase** in your IDE, starting with sharding the documents and creating the first story with the Scrum Master.

You can initiate the sharding process with the Product Owner or Scrum Master once in your IDE environment:
`*shard-doc docs/prd.md prd`
Then, you would activate the Scrum Master to create the first story: `*agent sm` and then `*create`.

Congratulations on reaching this milestone!