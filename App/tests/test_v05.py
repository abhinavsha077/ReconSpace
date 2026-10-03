import unittest

from reconspace.webapp import _html


class ObservatoryUiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = _html()

    def test_observatory_visual_system_and_result_rail_are_present(self):
        self.assertIn("ReconSpace Observatory — v0.5 visual system", self.html)
        self.assertIn('content:"SYSTEM MAP"', self.html)
        self.assertIn('content:"AUDIT MAP"', self.html)
        self.assertIn("grid-template-columns:224px minmax(0,1fr)", self.html)

    def test_ui_has_mobile_and_reduced_motion_modes(self):
        self.assertIn("@media(max-width:760px)", self.html)
        self.assertIn("@media(prefers-reduced-motion:reduce)", self.html)
        self.assertIn("scroll-behavior:auto!important", self.html)

    def test_tabs_support_roving_focus_and_arrow_keys(self):
        self.assertIn("function initTabs()", self.html)
        self.assertIn("aria-controls','view", self.html)
        self.assertIn("aria-labelledby=\"audit-tab-overview\"", self.html)
        self.assertIn("aria-orientation',matchMedia", self.html)
        self.assertIn("event.key==='ArrowDown'", self.html)
        self.assertIn("event.key==='Home'", self.html)

    def test_local_favicon_and_lower_idle_polling_need_no_network(self):
        self.assertIn('rel="icon" href="data:image/svg+xml,', self.html)
        self.assertIn("let nextPollMs=2400", self.html)
        self.assertIn("nextPollMs=800", self.html)


if __name__ == "__main__":
    unittest.main()
