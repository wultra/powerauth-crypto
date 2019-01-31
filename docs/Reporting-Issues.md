# Reporting Issues

In the ideal world, people read what you write. Try to help them understand your message by making your issue reports readable and to the point.

## One Problem, One Issue

Please submit one issue per problem. Different problems are most likely to be handled by different people. It's difficult to handle a multi-issue for all involved parties.

## Provide a Meaningful Summary

The summary of issue is very important, because it helps you:

- easily recognize the issue
- easily find the issue and identify duplicates
- judge an importance of issue

Please avoid "Your program is useless" or "It doesn't work" summaries. These force people to spend time to browse the issue and read through the whole report, instead of simply seeing what it is about and it takes time that could be used for fixing it.

## Provide a Detailed Description

The description should include the following technical information:

- Software version number
- Component that failed function
- Observed behavior
- Expected behavior
- Steps to reproduce the issue
- ... any other information potentially related to the issue

## Provide steps to reproduce

Please start to describe problem by detailed steps to reproduce:

```
1. Start PowerAuth server
2. Call `createActivation` method with following request ...
3. Call `blockActivation` method with following request ...
=> Following incorrect behavior is observed
```

You can save your time as well as ours and it will lead to fast solution.

## Use Attachments

Don't paste large files into the description. Copy the exception stack-trace or server log into a file, then attach this file. Keep attachments by the issue, avoid sharing them via separate channels (e-mail, Slack, gitter, ...).

## Read "How To Ask Questions The Smart Way"

It's a good idea to read [How To Ask Questions The Smart Way](http://www.catb.org/esr/faqs/smart-questions.html) - it's older stuff, but still valid.
