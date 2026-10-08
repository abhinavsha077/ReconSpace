import shutil
import subprocess
import unittest
from importlib.resources import files

from reconspace.webapp import _html


class CareExperienceTests(unittest.TestCase):
    def test_all_graphics_and_motion_are_packaged_locally(self):
        html = _html()
        self.assertNotIn('__CARE_MOTION__', html)
        self.assertNotIn('__SPACE_LENS__', html)
        for name in ('desktop', 'storage', 'protection', 'performance', 'applications', 'clutter'):
            self.assertTrue(files('reconspace').joinpath('assets', f'care-{name}.png').read_bytes().startswith(b'\x89PNG'))
        self.assertIn('id="motionPreference"', html)
        self.assertIn('prefers-reduced-motion', html)
        self.assertIn('visibilitychange', html)
        self.assertIn('id="railSelection"', html)
        self.assertIn("sessionStorage.setItem('rs_session'", html)
        self.assertIn('sequence!==navigationSequence', html)
        self.assertIn('CareMotion.stage(update', html)

    @unittest.skipUnless(shutil.which('node'), 'Node unavailable for JS regression')
    def test_storage_hierarchy_is_nonoverlapping_and_bounded_evidence(self):
        script = files('reconspace').joinpath('assets', 'space-lens.js').read_text(encoding='utf-8')
        case = r'''
const assert=require('node:assert/strict');
let REPORT={stats:{root:'C:\\'},top_directories:[
{path:'C:\\Users',size_bytes:100},{path:'C:\\Users\\Alice',size_bytes:90},
{path:'c:/Windows',size_bytes:200},{path:'C:\\Windows-old',size_bytes:50},
{path:'D:\\Other',size_bytes:300},{path:5,size_bytes:2},{path:'C:\\Bad',size_bytes:-1}
]};
assert.deepEqual(lensChildren('C:\\').map(row=>row.size_bytes),[200,100,50]);
assert.deepEqual(lensChildren('C:\\Users').map(row=>row.size_bytes),[90]);
assert.equal(lensChildren('C:\\Windows').length,0);
REPORT.top_directories=[];assert.equal(lensChildren('C:\\').length,0);
'''
        subprocess.run([shutil.which('node'), '-e', script + '\n' + case], check=True, capture_output=True, text=True)
