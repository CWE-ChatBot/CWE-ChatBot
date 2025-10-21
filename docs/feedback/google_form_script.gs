/**
 * Creates the Google Form "CWE Chatbot – Volunteer Feedback (Early Access)"
 * and links it to a Google Sheet with a Summary tab (Q/A/S averages + NPS).
 * Run createForm().
 *
 * Notes:
 * - File upload items may be unavailable for some accounts; script falls back to a links field.
 * - Branching: Q1 (Consent) → If "No", SUBMIT immediately.
 * - Use the custom menu in the sheet (CWE Feedback → Build/Refresh Summary) to rebuild metrics anytime.
 */

const CONFIG = {
  FORM_TITLE: 'CWE Chatbot – Volunteer Feedback (Early Access)',
  FORM_DESCRIPTION: 'Purpose: understand what users want from the CWE Chatbot; ~15–20 mins. Please avoid confidential data; anonymise examples. MITRE review: mid–end Oct; Volunteers: early Nov.',
  COLLECT_EMAIL: false,
  LIMIT_ONE_RESPONSE: false, // set true if internal only
  EDIT_AFTER_SUBMIT: true,
  SHOW_PROGRESS_BAR: true,
  SHUFFLE_QUESTIONS: false,
  TASK_BLOCK_COUNT: 5, // duplicate task block this many times
  RESPONSE_SHEET_NAME: 'CWE Chatbot – Volunteer Feedback (Responses)'
};

function createForm() {
  // Create the form
  const form = FormApp.create(CONFIG.FORM_TITLE)
    .setDescription(CONFIG.FORM_DESCRIPTION)
    .setProgressBar(CONFIG.SHOW_PROGRESS_BAR)
    .setAllowResponseEdits(CONFIG.EDIT_AFTER_SUBMIT)
    .setShuffleQuestions(CONFIG.SHUFFLE_QUESTIONS)
    .setCollectEmail(CONFIG.COLLECT_EMAIL)
    .setLimitOneResponsePerUser(CONFIG.LIMIT_ONE_RESPONSE)
    .setConfirmationMessage('Thanks for helping improve the CWE Chatbot. We’ll review P0/P1 items first and may contact you for clarification.');

  // ===== Section 1 — Introduction =====
  form.addPageBreakItem().setTitle('Introduction');

  // Q1 Consent (with branching)
  const consentItem = form.addMultipleChoiceItem()
    .setTitle('Consent to participate')
    .setRequired(true);
  const aboutYouPage = form.addPageBreakItem().setTitle('About You');
  consentItem.setChoices([
    consentItem.createChoice('Yes, I consent', aboutYouPage),
    // Directly submit the form on "No"
    consentItem.createChoice('No', FormApp.PageNavigationType.SUBMIT)
  ]);

  // ===== Section 2 — About You =====
  form.addTextItem().setTitle('Name').setRequired(false);
  form.addTextItem().setTitle('Email').setRequired(false).setValidation(
    FormApp.createTextValidation().requireTextIsEmail().build()
  );

  const roleItem = form.addMultipleChoiceItem().setTitle('Role / background').setRequired(true);
  roleItem.setChoices(['AppSec Engineer','Security Architect','Developer','Analyst','Researcher','Auditor','Other'].map(function(v){ return roleItem.createChoice(v); }));

  const orgItem = form.addMultipleChoiceItem().setTitle('Organisation type').setRequired(true);
  orgItem.setChoices(['Commercial','Government or Defense','Academia','Open Source','Other'].map(function(v){ return orgItem.createChoice(v); }));

  form.addParagraphTextItem().setTitle('Primary workflows with CWE/CVE today').setRequired(false);

  const famItem = form.addMultipleChoiceItem().setTitle('Familiarity with CWE taxonomy').setRequired(true);
  famItem.setChoices(['Novice','Intermediate','Advanced','SME'].map(function(v){ return famItem.createChoice(v); }));

  // ===== Section 3 — Expectations & First Impressions =====
  form.addPageBreakItem().setTitle('Expectations & First Impressions');
  form.addParagraphTextItem().setTitle('What were you hoping the chatbot would do for you?').setRequired(true);
  addScale(form, 'Onboarding made sense (how to start, examples, limits)', 1, 5, 'Very unclear', 'Very clear', true);
  addScale(form, 'Initial confidence: "I trust the chatbot to help me on real tasks."', 1, 5, 'Strongly disagree', 'Strongly agree', true);
  form.addParagraphTextItem().setTitle('Why / notes on first impressions').setRequired(false);

  // ===== Section 4 — Core Tasks =====
  form.addPageBreakItem().setTitle('Core Tasks (repeatable)');
  form.addSectionHeaderItem().setTitle('Instructions')
    .setHelpText('Perform 3–5 tasks matching your workflow. Paste prompts, rate results, add notes. Suggested: CVE→CWE, code snippet classification/fixes, compare two CWEs, mitigation checklist, crosswalk to ASVS/NIST/CERT, training blurb, cluster findings by CWE.');

  for (let i = 1; i <= CONFIG.TASK_BLOCK_COUNT; i++) {
    form.addSectionHeaderItem().setTitle('Task ' + i);
    form.addTextItem().setTitle('Task ' + i + ' — Task ID/Name').setRequired(true);
    form.addParagraphTextItem().setTitle('Task ' + i + ' — Your exact prompt(s)').setHelpText('Paste the exact prompt(s) you used.').setRequired(true);
    addScale(form, 'Task ' + i + ' — Result quality', 1, 5, 'Poor', 'Excellent', true);
    addScale(form, 'Task ' + i + ' — Perceived accuracy', 1, 5, 'Inaccurate', 'Accurate', true);
    addScale(form, 'Task ' + i + ' — Speed', 1, 5, 'Too slow', 'Very fast', true);
    addScale(form, 'Task ' + i + ' — Usefulness to your workflow', 1, 5, 'Not useful', 'Very useful', true);
    form.addTextItem()
      .setTitle('Task ' + i + ' — Time spent (minutes)')
      .setRequired(false)
      .setValidation(FormApp.createTextValidation().requireNumberGreaterThan(0).build());
    form.addParagraphTextItem().setTitle('Task ' + i + ' — What worked well?').setRequired(false);
    form.addParagraphTextItem().setTitle('Task ' + i + ' — What was missing or wrong?').setRequired(false);
    // Try to add file upload. If not available (consumer accounts / domain disabled), fall back to a text field for links.
    try {
      form.addFileUploadItem()
        .setTitle('Task ' + i + ' — Attach screenshots (optional)')
        .setHelpText('Images or PDFs. If this option is unavailable, use the next field to paste links.');
    } catch (e) {
      form.addParagraphTextItem()
        .setTitle('Task ' + i + ' — Paste link(s) to screenshots (optional)')
        .setHelpText('File upload isn’t available on this form. Paste Drive/issue tracker links instead.')
        .setRequired(false);
    }
  }

  // ===== Section 5 — Overall Usability & Fit =====
  form.addPageBreakItem().setTitle('Overall Usability & Fit');
  form.addGridItem()
    .setTitle('Rate the statements (1–5)')
    .setRows([
      'The interface is easy to understand.',
      'The chatbot’s citations/links improve trust.',
      'It handles follow-up questions/context well.',
      'It reduces my time vs current workflow.',
      'I would use this at least weekly for my job.'
    ])
    .setColumns(['1','2','3','4','5'])
    .setRequired(true);

  // ===== Section 6 — Accuracy, Coverage & Transparency =====
  form.addPageBreakItem().setTitle('Accuracy, Coverage & Transparency');
  addScale(form, 'When the chatbot cites sources, are they the right ones?', 1, 5, 'Rarely appropriate', 'Very appropriate', false);
  form.addParagraphTextItem().setTitle('Coverage gaps — Which CWE areas feel under-served or missing?').setRequired(false);
  form.addParagraphTextItem().setTitle('Hallucinations or wrong answers (log any)')
    .setHelpText('Include (a) your prompt, (b) expected/authoritative source, (c) model output, (d) impact (Low/Med/High).')
    .setRequired(false);

  // ===== Section 7 — Performance & Reliability =====
  form.addPageBreakItem().setTitle('Performance & Reliability');
  addScale(form, 'Response time overall', 1, 5, 'Too slow', 'Very fast', true);

  const stabItem = form.addMultipleChoiceItem().setTitle('Stability — errors, timeouts, or retries?').setRequired(true);
  stabItem.setChoices(['No issues','Some issues (describe below)','Frequent issues (describe below)'].map(function(v){ return stabItem.createChoice(v); }));

  form.addParagraphTextItem().setTitle('Details on stability issues (if any)').setRequired(false);

  const contItem = form.addMultipleChoiceItem().setTitle('Session continuity — remembered context within a session?').setRequired(true);
  contItem.setChoices(['Yes (works reliably)','Sometimes','No'].map(function(v){ return contItem.createChoice(v); }));

  form.addParagraphTextItem().setTitle('Examples of context handling (optional)').setRequired(false);

  // ===== Section 8 — Features & Workflow =====
  form.addPageBreakItem().setTitle('Features & Workflow');

  const featuresUsed = form.addCheckboxItem().setTitle('Which features did you use?').setRequired(false);
  featuresUsed.setChoices([
    'CWE lookup','CVE→CWE mapping','Code analysis','Crosswalks & controls','Mitigation guidance','Training content','Export or share','Citations','Staging-only feature(s)','Other'
  ].map(function(v){ return featuresUsed.createChoice(v); }));

  form.addCheckboxGridItem()
    .setTitle('Feature disposition (keep/remove/improve)')
    .setRows(['CWE lookup','CVE→CWE mapping','Code analysis','Crosswalks','Mitigations','Training content','Export/share','Citations','Other'])
    .setColumns(['Used','Keep','Remove','Improve'])
    .setRequired(false);

  form.addParagraphTextItem().setTitle('How to improve specific features?').setRequired(false);

  const integrations = form.addCheckboxItem().setTitle('Integrations/exports that would help').setRequired(false);
  integrations.setChoices(['GitHub Issues','Jira','SARIF','CSV','PDF','Markdown','JSON','Other'].map(function(v){ return integrations.createChoice(v); }));

  form.addParagraphTextItem().setTitle('Security/privacy concerns or requirements').setRequired(false);
  form.addParagraphTextItem().setTitle('If limited to 3 improvements before GA, what would they be?').setRequired(true);

  // ===== Section 9 — Value & Adoption =====
  form.addPageBreakItem().setTitle('Value & Adoption');
  addScale(form, 'Likelihood to recommend (NPS)', 0, 10, 'Not at all likely (0)', 'Extremely likely (10)', true);

  const prodItem = form.addMultipleChoiceItem().setTitle('Would you use this in production today?').setRequired(true);
  prodItem.setChoices(['Yes','No','Maybe (depends)'].map(function(v){ return prodItem.createChoice(v); }));

  form.addParagraphTextItem().setTitle('Why or why not?').setRequired(false);
  form.addParagraphTextItem().setTitle('Primary value delivered (or potential)').setRequired(false);
  form.addParagraphTextItem().setTitle('What would make this a “must-have” for you?').setRequired(false);
  form.addParagraphTextItem().setTitle('Anything else we should know?').setRequired(false);

  // ===== Section 10 — Prioritization (P0–P3) =====
  form.addPageBreakItem().setTitle('Prioritization (P0–P3)');
  for (let i = 1; i <= 5; i++) {
    form.addSectionHeaderItem().setTitle('Item ' + i);
    form.addTextItem().setTitle('Item ' + i + ' — Title/Item').setRequired(true);
    form.addParagraphTextItem().setTitle('Item ' + i + ' — Description').setRequired(false);

    const prio = form.addListItem().setTitle('Item ' + i + ' — Priority').setRequired(true);
    prio.setChoices(['P0','P1','P2','P3'].map(function(v){ return prio.createChoice(v); }));

    const impact = form.addMultipleChoiceItem().setTitle('Item ' + i + ' — Impact if fixed').setRequired(false);
    impact.setChoices(['Low','Medium','High'].map(function(v){ return impact.createChoice(v); }));

    const effort = form.addMultipleChoiceItem().setTitle('Item ' + i + ' — Estimated effort (guess)').setRequired(false);
    effort.setChoices(['S','M','L'].map(function(v){ return effort.createChoice(v); }));
  }

  // ===== Section 11 — Consent for Follow-up (optional) =====
  form.addPageBreakItem().setTitle('Consent for Follow-up (optional)');
  const follow = form.addMultipleChoiceItem().setTitle('May we contact you for a 15–30 min interview?').setRequired(false);
  follow.setChoices(['Yes','No'].map(function(v){ return follow.createChoice(v); }));

  form.addTextItem().setTitle('Best contact method and time zone').setHelpText('e.g., email or phone; timezone (e.g., Europe/Dublin)').setRequired(false);

  // ===== Link to Google Sheet and build Summary =====
  const ss = SpreadsheetApp.create(CONFIG.RESPONSE_SHEET_NAME);
  form.setDestination(FormApp.DestinationType.SPREADSHEET, ss.getId());

  // Try to build the Summary sheet immediately (works once headers exist)
  try {
    buildOrRefreshSummary_(form, ss);
  } catch (e) {
    Logger.log('Summary setup deferred: ' + (e && e.message ? e.message : e));
  }

  Logger.log('Form created: ' + form.getEditUrl());
  Logger.log('Response URL: ' + form.getPublishedUrl());
  Logger.log('Spreadsheet: ' + ss.getUrl());
}

/** Helper to add a linear scale item */
function addScale(form, title, lower, upper, leftLabel, rightLabel, required) {
  form.addScaleItem()
    .setTitle(title)
    .setBounds(lower, upper)
    .setLabels(leftLabel, rightLabel)
    .setRequired(!!required);
}

/** Adds a custom menu to rebuild the Summary at any time */
function onOpen() {
  SpreadsheetApp.getUi().createMenu('CWE Feedback')
    .addItem('Build/Refresh Summary', 'buildSummaryFromActiveSpreadsheet')
    .addToUi();
}

/** Convenience: run this from the sheet linked to the Form */
function buildSummaryFromActiveSpreadsheet() {
  const ss = SpreadsheetApp.getActive();
  const formUrl = ss.getFormUrl();
  if (!formUrl) throw new Error('This spreadsheet is not linked to a Form.');
  const form = FormApp.openByUrl(formUrl);
  buildOrRefreshSummary_(form, ss);
}

/** Core: Create or refresh the Summary sheet with Q/A/S averages and NPS */
function buildOrRefreshSummary_(form, ss) {
  const RESP_SHEET_NAME = 'Form Responses 1';
  const resSheet = ss.getSheetByName(RESP_SHEET_NAME);
  if (!resSheet) throw new Error('Response sheet not found yet. Submit one response, then run "Build/Refresh Summary".');

  const lastCol = resSheet.getLastColumn();
  if (lastCol === 0) throw new Error('Response sheet has no headers yet. Submit one response, then run again.');

  // Read header row to identify columns
  const headers = resSheet.getRange(1, 1, 1, lastCol).getValues()[0];
  const colLetter = function(idx){ return columnToLetter_(idx + 1); }; // 0-based idx → A1 letter

  // Collect columns for all Task scales dynamically by header title
  const qualityCols = [];
  const accuracyCols = [];
  const speedCols   = [];
  var npsCol = null;

  headers.forEach(function(h, i){
    if (!h) return;
    const t = String(h);
    if (/^Task \d+ — Result quality$/i.test(t)) qualityCols.push(colLetter(i));
    if (/^Task \d+ — Perceived accuracy$/i.test(t)) accuracyCols.push(colLetter(i));
    if (/^Task \d+ — Speed$/i.test(t)) speedCols.push(colLetter(i));
    if (/^Likelihood to recommend \(NPS\)$/i.test(t)) npsCol = colLetter(i);
  });

  // Create or clear Summary sheet
  const name = 'Summary';
  let sum = ss.getSheetByName(name);
  if (!sum) sum = ss.insertSheet(name);
  sum.clear();

  // Helper to make an AVERAGE over multiple columns, skipping blanks
  function avgFormulaForCols(cols) {
    if (!cols.length) return '"No matching columns yet"';
    var parts = cols.map(function(c){ return "'" + RESP_SHEET_NAME + "'!" + c + "2:" + c; });
    var ranges = parts.join(';');
    // Use AVERAGE over a vertical stack of all columns
    return "=IFERROR(AVERAGE(TONUMBER(TOCOL({" + ranges + "},1))),\"\")";
  }

  // Write metrics
  sum.getRange('A1').setValue('Metric');
  sum.getRange('B1').setValue('Value');
  sum.getRange('A2').setValue('Quality avg (1–5)');
  sum.getRange('B2').setFormula(avgFormulaForCols(qualityCols));
  sum.getRange('A3').setValue('Accuracy avg (1–5)');
  sum.getRange('B3').setFormula(avgFormulaForCols(accuracyCols));
  sum.getRange('A4').setValue('Speed avg (1–5)');
  sum.getRange('B4').setFormula(avgFormulaForCols(speedCols));

  sum.getRange('A5').setValue('Responses (count)');
  sum.getRange('B5').setFormula("=IFERROR(MAX(ROW(FILTER('" + RESP_SHEET_NAME + "'!A:A,'" + RESP_SHEET_NAME + "'!A:A<>\"\")))-1,0)");

  sum.getRange('A6').setValue('NPS (–1 to +1)');
  if (npsCol) {
    var npsFormula = "=IFERROR((COUNTIF(FILTER('" + RESP_SHEET_NAME + "'!" + npsCol + ":" + npsCol + ",ISNUMBER('" + RESP_SHEET_NAME + "'!" + npsCol + ":" + npsCol + ")),\">=9\")-" +
                     "COUNTIF(FILTER('" + RESP_SHEET_NAME + "'!" + npsCol + ":" + npsCol + ",ISNUMBER('" + RESP_SHEET_NAME + "'!" + npsCol + ":" + npsCol + ")),\"<=6\")) / " +
                     "COUNTA(FILTER('" + RESP_SHEET_NAME + "'!" + npsCol + ":" + npsCol + ",ISNUMBER('" + RESP_SHEET_NAME + "'!" + npsCol + ":" + npsCol + "))),\"\")";
    sum.getRange('B6').setFormula(npsFormula);
  } else {
    sum.getRange('B6').setValue('NPS question not found yet');
  }

  // Basic formatting
  sum.getRange('A1:B1').setFontWeight('bold');
  sum.autoResizeColumn(1);
  sum.autoResizeColumn(2);
}

function columnToLetter_(column) {
  let temp = '';
  let col = column;
  while (col > 0) {
    let rem = (col - 1) % 26;
    temp = String.fromCharCode(65 + rem) + temp;
    col = Math.floor((col - rem) / 26);
  }
  return temp;
}
