'use strict';
const rules = require('../.github/issue-policy.json');

function issueNumbers(body = '') {
  const numbers = [...body.matchAll(/^Closes #([1-9][0-9]*)[ \t]*$/gm)].map(m => Number(m[1]));
  if (!numbers.length) throw new Error('Include a standalone Closes #<number> line for a local issue.');
  return [...new Set(numbers)];
}

function validateIssue(issue) {
  if (issue.pull_request) throw new Error('#' + issue.number + ' is a pull request, not an issue.');
  if (issue.state !== 'open') throw new Error('#' + issue.number + ' must be open.');
  const rule = rules.find(r => issue.title.startsWith(r.prefix));
  if (!rule || !issue.title.slice(rule.prefix.length).trim()) throw new Error('Issue title must include a form prefix and a descriptive title.');
  const sections = new Map();
  for (const match of (issue.body || '').matchAll(/^### (.+)\r?\n([\s\S]*?)(?=^### |$(?![\s\S]))/gm)) {
    if (sections.has(match[1].trim())) throw new Error('Duplicate issue section: ' + match[1]);
    sections.set(match[1].trim(), match[2].trim());
  }
  for (const heading of rule.requiredSections) {
    const answer = sections.get(heading);
    if (!answer || /^_?No response_?$/i.test(answer) || /^<!--[^]*-->$/.test(answer)) {
      throw new Error('Issue #' + issue.number + ' needs a substantive answer for: ' + heading);
    }
  }
}

async function checkPullRequest({ github, context }) {
  const pr = context.payload.pull_request;
  if (!pr) throw new Error('This check requires a pull request event.');
  for (const issue_number of issueNumbers(pr.body || '')) {
    const { data: issue } = await github.rest.issues.get({ ...context.repo, issue_number });
    validateIssue(issue);
    console.log('Validated issue #' + issue_number + ': ' + issue.title);
  }
}
async function checkDispatchedPullRequest({ github, context, number }) {
  if (!/^[1-9][0-9]*$/.test(String(number))) throw new Error('A valid pull request number is required.');
  const { data: pr } = await github.rest.pulls.get({ ...context.repo, pull_number: Number(number) });
  if (pr.state !== 'open' || pr.head.repo?.full_name !== context.repo.owner + '/' + context.repo.repo ||
      pr.head.sha !== context.sha || context.ref !== 'refs/heads/' + pr.head.ref ||
      pr.base.ref !== context.payload.repository.default_branch) {
    throw new Error('Dispatched policy must run on the open local PR head targeting the default branch.');
  }
  await checkPullRequest({ github, context: { ...context, payload: { ...context.payload, pull_request: pr } } });
}
module.exports = { issueNumbers, validateIssue, checkPullRequest, checkDispatchedPullRequest };
