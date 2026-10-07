import os
import sys
import unittest
from PIL import Image

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from scripts.generate_slide_deck_assets import (
    generate_presentation_performance_figure,
    generate_presentation_slide_deck_markdown
)
from scripts.generate_thesis_chapters import main as generate_all_thesis_chapters


class TestThesisAndPresentationAssets(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Ensure all assets and chapters are compiled
        generate_all_thesis_chapters()
        generate_presentation_performance_figure()
        generate_presentation_slide_deck_markdown()

    def test_01_architecture_diagram_resolution(self):
        """Verifies architecture_diagram.png exists, is high-resolution 300 DPI, and exceeds 100 KB."""
        png_path = os.path.join(PROJECT_ROOT, "architecture_diagram.png")
        self.assertTrue(os.path.exists(png_path), "architecture_diagram.png missing")
        self.assertGreater(os.path.getsize(png_path), 100000)

        with Image.open(png_path) as img:
            self.assertGreaterEqual(img.width, 4000)
            self.assertGreaterEqual(img.height, 2500)

    def test_02_workflow_diagram_resolution(self):
        """Verifies end_to_end_structure.png exists, is high-resolution 300 DPI, and exceeds 100 KB."""
        png_path = os.path.join(PROJECT_ROOT, "end_to_end_structure.png")
        self.assertTrue(os.path.exists(png_path), "end_to_end_structure.png missing")
        self.assertGreater(os.path.getsize(png_path), 100000)

        with Image.open(png_path) as img:
            self.assertGreaterEqual(img.width, 4000)
            self.assertGreaterEqual(img.height, 2500)

    def test_03_performance_summary_figure(self):
        """Verifies final_presentation_performance_summary.png exists and is a multi-panel figure."""
        summary_png = os.path.join(PROJECT_ROOT, "data", "benchmarks", "final_presentation_performance_summary.png")
        self.assertTrue(os.path.exists(summary_png), "Performance summary figure missing")
        self.assertGreater(os.path.getsize(summary_png), 100000)

        with Image.open(summary_png) as img:
            self.assertGreaterEqual(img.width, 3500)
            self.assertGreaterEqual(img.height, 2500)

    def test_04_viva_presentation_slides_deck(self):
        """Verifies docs/FINAL_VIVA_PRESENTATION_SLIDES.md exists, exceeds 15 KB, and contains all 18 slides."""
        slides_path = os.path.join(PROJECT_ROOT, "docs", "FINAL_VIVA_PRESENTATION_SLIDES.md")
        self.assertTrue(os.path.exists(slides_path), "Slides markdown missing")
        self.assertGreater(os.path.getsize(slides_path), 15000)

        with open(slides_path, "r", encoding="utf-8") as f:
            content = f.read()

        for slide_num in range(1, 19):
            self.assertIn(f"SLIDE {slide_num}:", content, f"Slide {slide_num} missing from deck")

        self.assertIn("APPENDIX: Viva Defense Q&A Cheat Sheet", content)
        self.assertIn("Killourhy & Maxion", content)

    def test_05_individual_thesis_chapters(self):
        """Verifies all 6 individual thesis chapters exist and contain rigorous content (> 4 KB each)."""
        thesis_dir = os.path.join(PROJECT_ROOT, "docs", "thesis")
        expected_chapters = [
            "Chapter_1_Introduction.md",
            "Chapter_2_Literature_Review.md",
            "Chapter_3_System_Design_and_Methodology.md",
            "Chapter_4_Implementation_Details.md",
            "Chapter_5_Experimental_Results_and_Discussion.md",
            "Chapter_6_Conclusion_and_Future_Scope.md"
        ]

        for ch in expected_chapters:
            ch_path = os.path.join(thesis_dir, ch)
            self.assertTrue(os.path.exists(ch_path), f"Missing {ch}")
            self.assertGreater(os.path.getsize(ch_path), 4000, f"{ch} is too small")

    def test_06_monolithic_master_thesis_document(self):
        """Verifies docs/thesis/Thesis_Master_Document.md exists, exceeds 35 KB, and includes table of contents."""
        master_doc = os.path.join(PROJECT_ROOT, "docs", "thesis", "Thesis_Master_Document.md")
        self.assertTrue(os.path.exists(master_doc), "Thesis_Master_Document.md missing")
        self.assertGreater(os.path.getsize(master_doc), 35000)

        with open(master_doc, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn("TABLE OF CONTENTS", content)
        self.assertIn("CHAPTER 1: INTRODUCTION", content)
        self.assertIn("CHAPTER 2: LITERATURE REVIEW", content)
        self.assertIn("CHAPTER 3: SYSTEM DESIGN AND METHODOLOGY", content)
        self.assertIn("CHAPTER 4: IMPLEMENTATION DETAILS", content)
        self.assertIn("CHAPTER 5: EXPERIMENTAL RESULTS AND DISCUSSION", content)
        self.assertIn("CHAPTER 6: CONCLUSION AND FUTURE SCOPE", content)
        self.assertIn("REFERENCES AND BIBLIOGRAPHY", content)


if __name__ == "__main__":
    unittest.main()
