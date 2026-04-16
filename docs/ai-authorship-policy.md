# AI Authorship Policy

## Purpose

This course uses an authorship-verification workflow instead of trying to
"detect AI." The goal is to allow limited support while making sure your final
submission is still your own work.

## Allowed AI use

You may use AI for limited support tasks such as:

- concept explanations
- Django or web security study help
- debugging hints
- documentation lookup
- refactoring suggestions that you review and understand
- wording help for documentation

## Disallowed AI use

You may not:

- ask AI to design and implement the entire assignment on their behalf
- submit code they do not understand and cannot defend
- use AI to generate large portions of the solution without meaningful review
- hide or omit material AI assistance in the pull request

## Student obligations

Your submission must include:

- a linked assignment issue
- a short design note before or at the start of implementation
- meaningful commit history that shows progress over time
- validation notes describing how the work was checked
- disclosure of any AI assistance used

You must also be able to explain:

- the architecture and main code paths
- the security choices you made
- why built-in Django mechanisms were or were not used
- the tests or checks you relied on
- the edits you made after any AI-generated suggestion

## Why follow this carefully

Your work may receive closer review if:

- sudden changes in code quality or style
- commit history with little visible iteration
- security rationale that does not match the implementation
- polished prose combined with weak technical explanation
- inability to answer questions about the submitted code

## Defense step

You may be asked to complete a short authorship defense, such as a 3-5 minute
walkthrough or short written follow-up. Typical prompts include:

- Why did you choose this view, form, or model structure?
- Where is access control enforced?
- What would break if CSRF protection were removed here?
- Which test or check would fail if this route became public?
