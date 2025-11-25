import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';

interface AnalysisResult {
  indicator: string;
  description: string;
  severity: 'Low' | 'Medium' | 'High';
  confidence: number;
  details: string;
}

@Component({
  selector: 'app-anti-forensics-detector',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './anti-forensics-detector.html',
  styleUrls: ['./anti-forensics-detector.scss']
})
export class AntiForensicsDetectorComponent {
  analysisPath: string = '';
  selectedOption: 'full' | 'quick' | 'custom' = 'full';
  analysisResults: AnalysisResult[] = [];

  runAnalysis() {
    if (!this.analysisPath) {
      alert('Please enter a file or directory path to analyze.');
      return;
    }

    // Simulate analysis based on selected option and path
    this.analysisResults = []; // Clear previous results

    if (this.selectedOption === 'full' || this.selectedOption === 'quick') {
      this.analysisResults.push({
        indicator: 'Hidden Data Streams',
        description: 'Detected potential Alternate Data Streams (ADS) in a file.',
        severity: 'High',
        confidence: 0.86,
        details: `Path: ${this.analysisPath}\nStream Name: secret.txt`,
      });
      this.analysisResults.push({
        indicator: 'Timestomp Anomaly',
        description: 'File timestamps appear to be manipulated.',
        severity: 'Medium',
        confidence: 0.72,
        details: `Path: ${this.analysisPath}\nOriginal Creation: 2023-01-01, Modified: 2023-10-26`,
      });
    } else if (this.selectedOption === 'custom') {
      this.analysisResults.push({
        indicator: 'Custom Rule Match',
        description: 'A custom anti-forensics rule was triggered.',
        severity: 'Low',
        confidence: 0.41,
        details: `Path: ${this.analysisPath}\nRule: Check for specific registry key changes`,
      });
    }

    alert(`Analysis complete for ${this.analysisPath} with ${this.selectedOption} scan.`);
  }
}
