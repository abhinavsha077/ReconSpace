import shutil
import subprocess
import unittest
from importlib.resources import files

from reconspace.webapp import _html


class GuidedCareTests(unittest.TestCase):
    def test_guided_resources_and_scan_recovery_are_in_html(self):
        html = _html()
        self.assertNotIn('__CARE_FLOW__', html)
        for element in ('flowNavigation', 'flowContent', 'flowDialog'):
            self.assertIn(f'id="{element}"', html)
        for hook in ('CareFlow.enterPage(name)', 'CareFlow.scanFailed()',
                     'CareFlow.scanFinished(currentPage)', 'CareFlow.cancelled()', 'CareFlow.failed()'):
            self.assertIn(hook, html)
        self.assertIn('body[data-flow-stage=review]', html)

    @unittest.skipUnless(shutil.which('node'), 'Node unavailable for JS regression')
    def test_review_rows_estimates_and_report_replacement(self):
        script = files('reconspace').joinpath('assets', 'care-flow.js').read_text(encoding='utf-8')
        # Expose private pure/state helpers only inside this isolated test process.
        script = script.replace('return {enterPage,',
                                'return {testing:{rows,estimate,selectable,syncReport,selected,planText},enterPage,')
        prelude = """
const assert=require('node:assert/strict');
let REPORT={stats:{root:'T:/fixture'},findings:[null,[],
 {title:'Cache',disposition:'probably_safe_cleanup',estimated_reclaimable_bytes:12},
 {title:'Archive',disposition:'manual_review'},
 {title:'Environment',disposition:'intentional_tooling'}],
 duplicates:[{paths:['a','b'],reclaimable_bytes:64}]};
const renderCareResults=()=>{},renderMetrics=()=>{};
let currentPage='reports',destination=null;
const navigatePage=page=>{destination=page;};
"""
        cases = """
const t=CareFlow.testing;t.syncReport();
assert.equal(t.rows('cleanup','safe').length,1);
assert.equal(t.rows('cleanup','manual').length,1);
const protectedRow=t.rows('cleanup','protected')[0];
assert.equal(t.selectable(protectedRow),false);
assert.equal(t.estimate(t.rows('clutter','duplicates')[0]),64);
const row=t.rows('cleanup','safe')[0];t.selected.set(row.key,row);
assert.match(t.planText(),/PLAN ONLY — NO EXECUTION/);
assert.match(t.planText(),/Cache/);
const previous=REPORT;CareFlow.scanStarted();REPORT=null;t.syncReport();
assert.equal(t.selected.size,1);CareFlow.scanFailed();
assert.equal(REPORT,previous);assert.equal(t.selected.size,1);
CareFlow.scanStarted();REPORT=null;
assert.equal(CareFlow.failed(),true);assert.equal(REPORT,previous);
assert.equal(destination,'reports');assert.equal(t.selected.size,1);
REPORT={findings:[]};t.syncReport();assert.equal(t.selected.size,0);
assert.deepEqual(t.rows('cleanup','safe'),[]);
"""
        subprocess.run([shutil.which('node'), '-e', prelude + script + cases],
                       check=True, capture_output=True, text=True)
