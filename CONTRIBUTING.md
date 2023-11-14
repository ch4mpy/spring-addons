# Contributing
Thanks for considering to contribute!

## Code of conduct
Examples of behavior that contributes to creating a positive environment include:
- Using welcoming and inclusive language
- Being respectful of differing viewpoints and experiences
- Gracefully accepting constructive criticism
- Focusing on what is best for the community
- Showing empathy towards other community members

Examples of unacceptable behavior by participants include:
- The use of sexualized language or imagery and unwelcome sexual attention or advances
- Trolling, insulting/derogatory comments, and personal or political attacks
- Public or private harassment
- Publishing others' private information, such as a physical or electronic address, without explicit permission
- Other conduct which could reasonably be considered inappropriate in a professional setting

This Code of Conduct is adapted from the [Contributor Covenant](http://contributor-covenant.org/), version 1.4, available at http://contributor-covenant.org/version/1/4

## How to Contribute
### Create an Issue
Reporting an issue or making a feature request is a great way to contribute. 
Your feedback and the conversations that result from it provide a continuous flow of ideas.
However, before creating a ticket, please take the time to ask and research first.

### Submit a Pull Request
Should you create an issue first? No, just create the pull request and use the description to provide context and motivation, as you would for an issue.
If you want to start a discussion first or have already created an issue, once a pull request is created, we will close the issue as superseded by the pull request, and the discussion about the issue will continue under the pull request.

Always check out the main branch and submit pull requests against it. Backports to prior versions will be considered on a case-by-case basis and reflected as the fix version in the issue tracker.

Choose the granularity of your commits consciously and squash commits that represent multiple edits or corrections of the same logical change. See Rewriting History section of Pro Git for an overview of streamlining the commit history.

If there is a prior issue, reference the GitHub issue number in the description of the pull request.

If accepted, your contribution may be heavily modified as needed prior to merging. You will likely retain author attribution for your Git commits granted that the bulk of your changes remain intact. You may also be asked to rework the submission.

If asked to make corrections, simply push the changes against the same branch, and your pull request will be updated. In other words, you do not need to create a new pull request when asked to make changes.

## Build from source
`mvn install` with Maven 3 and JDK 17 or above should be enough to build, run tests and package.
