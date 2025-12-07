import { Component, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { HttpClient, HttpClientModule, HttpErrorResponse } from '@angular/common/http';

interface AnalysisResult {
  indicator: string;
  description: string;
  severity: 'Low' | 'Medium' | 'High' | 'Critical';
  confidence: number;
  details: string;
  content_preview?: string;
}

interface StreamData {
  name: string;
  size_bytes: number;
  stream_type: string;
  risk_score: number;
  content_preview?: string;
  is_executable?: boolean;
  is_encrypted?: boolean;
  hash_md5?: string;
  hash_sha256?: string;
  entropy?: number;
  creation_time?: string;
  modification_time?: string;
}

interface RiskAssessment {
  risk_level: 'low' | 'medium' | 'high' | 'critical';
  score: number;
  description: string;
  details?: {
    total_streams: number;
    critical_streams: number;
    high_risk_streams: number;
    medium_risk_streams: number;
    low_risk_streams: number;
    executable_streams: number;
    encrypted_streams: number;
    total_size_bytes: number;
    total_size_human: string;
  };
}

interface ScanSummary {
  total_files_scanned: number;
  files_with_ads: number;
  total_ads_streams: number;  // ADD THIS
  scan_timestamp: string;
}

interface ApiResponse {
  success: boolean;
  filename?: string;
  data: {
    ads_found?: boolean;
    streams?: StreamData[];
    risk_assessment?: RiskAssessment;
    recommendations?: string[];
    summary?: string;
    file_path?: string;
    file_size?: number;
    total_streams?: number;
    total_ads_size_human?: string;
    analysis_methods?: any[];
    platform?: string;
    timestamp?: string;
    error?: string;
    scan_summary?: ScanSummary;
  };
  detail?: string;
  selected_detectors?: string[];
  message?: string;
  error?: string;
}

interface DetectorOption {
  name: string;
  value: string;
  category: string;
  subOptions?: DetectorOption[];
}

@Component({
  selector: 'app-anti-forensics-detector',
  standalone: true,
  imports: [CommonModule, FormsModule, HttpClientModule],
  templateUrl: './anti-forensics-detector.html',
  styleUrls: ['./anti-forensics-detector.scss']
})
export class AntiForensicsDetectorComponent {
  analysisPath: string = '';
  
  // Keep all your original options
  availableDetectors: DetectorOption[] = [
    { 
      name: 'Alternate Data Streams (ADS)', 
      value: 'ads_detector',
      category: 'file_system',
      subOptions: [
        { name: 'PowerShell Detection', value: 'powershell', category: 'ads_method' },
        { name: 'Win32 API Detection', value: 'win32api', category: 'ads_method' },
        { name: 'Pattern Matching', value: 'pattern', category: 'ads_method' }
      ]
    },
    { name: 'Data Wiping', value: 'data_wiping_detector', category: 'file_system' },
    { name: 'Encryption', value: 'encryption_detector', category: 'content' },
    { name: 'Fake Metadata', value: 'fake_metadata_detector', category: 'metadata' },
    { name: 'Hidden Files', value: 'hidden_file_detector', category: 'file_system' },
    { name: 'Log Tampering', value: 'log_tampering_detector', category: 'logs' },
    { name: 'Steganography', value: 'stego_detector', category: 'content' },
    { name: 'Suspicious Rename', value: 'suspicious_rename_detector', category: 'file_system' },
    { name: 'Timestomp', value: 'timestomp_detector', category: 'metadata' },
  ];
  
  // Separate selection for ADS methods
  selectedDetectors: string[] = [];
  selectedADSMethods: string[] = ['powershell']; // Default ADS method
  analysisResults: AnalysisResult[] = [];
  riskAssessment: RiskAssessment | null = null;
  recommendations: string[] = [];
  summary: string = '';
  selectedFile: File | null = null;
  isLoading: boolean = false;
  isScanningDirectory: boolean = false;
  
  // Use the correct backend URL (Flask runs on port 5000)
  private readonly API_BASE_URL = 'http://localhost:5000/api/ads';
  private http = inject(HttpClient);

  // PUBLIC METHODS FOR TEMPLATE
  formatSize(bytes: number): string {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }

  showDetails(result: AnalysisResult): void {
    alert(`Stream Details:\n\n${result.details}`);
  }

  onFileSelected(event: Event): void {
    const element = event.target as HTMLInputElement;
    if (element.files && element.files.length > 0) {
      this.selectedFile = element.files[0];
      this.analysisPath = this.selectedFile.name;
    } else {
      this.selectedFile = null;
    }
  }

  onDetectorChange(detectorValue: string, event: Event): void {
    const isChecked = (event.target as HTMLInputElement).checked;
    if (isChecked) {
      if (!this.selectedDetectors.includes(detectorValue)) {
        this.selectedDetectors.push(detectorValue);
      }
    } else {
      this.selectedDetectors = this.selectedDetectors.filter(d => d !== detectorValue);
      
      // If ADS detector is deselected, clear ADS methods
      if (detectorValue === 'ads_detector') {
        this.selectedADSMethods = [];
      }
    }
  }

  onADSMethodChange(methodValue: string, event: Event): void {
    const isChecked = (event.target as HTMLInputElement).checked;
    if (isChecked) {
      if (!this.selectedADSMethods.includes(methodValue)) {
        this.selectedADSMethods.push(methodValue);
      }
    } else {
      this.selectedADSMethods = this.selectedADSMethods.filter(m => m !== methodValue);
    }
  }

  isADSSelected(): boolean {
    return this.selectedDetectors.includes('ads_detector');
  }

  clearSelection(): void {
    this.selectedDetectors = [];
    this.selectedADSMethods = ['powershell'];
    this.analysisResults = [];
    this.riskAssessment = null;
    this.recommendations = [];
    this.summary = '';
    this.analysisPath = '';
    this.selectedFile = null;
    this.isScanningDirectory = false;
    
    // Reset file input
    const fileInput = document.getElementById('fileUpload') as HTMLInputElement;
    if (fileInput) {
      fileInput.value = '';
    }
  }

  runAnalysis(): void {
    // Validate input
    if (!this.analysisPath.trim() && !this.selectedFile) {
      alert('Please enter a file or directory path, or upload a file to analyze.');
      return;
    }
    
    if (this.selectedDetectors.length === 0) {
      alert('Please select at least one detection option.');
      return;
    }

    // Validate ADS methods if ADS detector is selected
    if (this.isADSSelected() && this.selectedADSMethods.length === 0) {
      alert('Please select at least one ADS detection method.');
      return;
    }

    this.analysisResults = [];
    this.riskAssessment = null;
    this.recommendations = [];
    this.summary = '';
    this.isLoading = true;

    try {
      if (this.selectedFile) {
        this.analyzeFile();
      } else {
        this.analyzePath();
      }
    } catch (error) {
      console.error('Analysis error:', error);
      this.isLoading = false;
      alert('Failed to start analysis. Please check your inputs.');
    }
  }

  private analyzeFile(): void {
    const formData = new FormData();
    formData.append('file', this.selectedFile!, this.selectedFile!.name);
    
    // For ADS detector, send ADS methods
    if (this.isADSSelected()) {
      formData.append('detectors', JSON.stringify(this.selectedADSMethods));
    } else {
      // For other detectors, send them as-is (they'll need different endpoints)
      formData.append('detectors', JSON.stringify(this.selectedDetectors));
    }

    this.http.post<ApiResponse>(`${this.API_BASE_URL}/upload-and-detect`, formData).subscribe({
      next: (response: ApiResponse) => {
        this.handleApiResponse(response);
      },
      error: (error: HttpErrorResponse) => {
        this.handleApiError(error);
      }
    });
  }

  private analyzePath(): void {
    // Check if path is a directory
    const isDirectory = this.analysisPath.includes('\\') || 
                       this.analysisPath.includes('/') ||
                       this.analysisPath.endsWith('\\') ||
                       this.analysisPath.endsWith('/');
    
    this.isScanningDirectory = isDirectory;

    // Prepare payload based on selected detectors
    let payload: any;
    
    if (this.isADSSelected()) {
      // ADS detector with methods
      payload = {
        file_path: this.analysisPath.trim(),
        selected_detectors: this.selectedADSMethods,
        use_win32api: this.selectedADSMethods.includes('win32api'),
        scan_directory: isDirectory
      };
    } else {
      // Other detectors (will need different API endpoints)
      payload = {
        file_path: this.analysisPath.trim(),
        selected_detectors: this.selectedDetectors,
        scan_directory: isDirectory
      };
    }

    this.http.post<ApiResponse>(`${this.API_BASE_URL}/detect`, payload, {
      headers: { 'Content-Type': 'application/json' }
    }).subscribe({
      next: (response: ApiResponse) => {
        this.handleApiResponse(response);
      },
      error: (error: HttpErrorResponse) => {
        this.handleApiError(error);
      }
    });
  }

  private handleApiResponse(response: ApiResponse): void {
    this.isLoading = false;
    
    if (response.success && response.data) {
      const data = response.data;
      
      // Check if this is an ADS response
      if (data.ads_found !== undefined) {
        this.handleADSResponse(data);
      } else {
        // Handle other detector responses
        this.handleOtherDetectorResponse(data);
      }
      
    } else {
      const errorMsg = response.detail || response.data?.error || response.error || response.message || 'Unknown error';
      alert(`Analysis failed: ${errorMsg}`);
    }
  }

  private handleADSResponse(data: any): void {
    // Check if ADS were found
    if (!data.ads_found) {
      const targetName = this.selectedFile ? this.selectedFile.name : this.analysisPath;
      this.summary = `No ADS streams found in ${targetName}`;
      this.recommendations = data.recommendations || ['No action required'];
      alert(`Analysis complete for ${targetName}. No ADS streams found.`);
      return;
    }
    
    // Process streams if found
    if (data.streams && data.streams.length > 0) {
      this.analysisResults = data.streams.map((stream: StreamData) => ({
        indicator: stream.name,
        description: `${stream.stream_type} | Size: ${this.formatSize(stream.size_bytes)}`,
        severity: this.calculateSeverity(stream.risk_score),
        confidence: stream.risk_score,
        details: this.formatStreamDetails(stream),
        content_preview: stream.content_preview
      }));
    }
    
    // Store additional data
    this.riskAssessment = data.risk_assessment || null;
    this.recommendations = data.recommendations || [];
    this.summary = data.summary || `Found ${data.total_streams || 0} ADS streams`;
    
    const targetName = this.selectedFile ? this.selectedFile.name : this.analysisPath;
    alert(`Analysis complete for ${targetName}. Found ${data.total_streams || 0} ADS streams.`);
  }

  private handleOtherDetectorResponse(data: any): void {
    // TODO: Implement handling for other detectors
    // This will depend on how your other detectors return data
    alert('Other detector analysis completed (not yet implemented fully).');
  }

  private handleApiError(error: HttpErrorResponse): void {
    this.isLoading = false;
    console.error('API Error:', error);
    
    if (error.status === 0) {
      alert('Cannot connect to the backend server. Please make sure the Flask server is running on port 5000.');
    } else if (error.status === 400) {
      const errorMsg = error.error?.detail || error.error?.error || 'Invalid request';
      alert(`Bad request: ${errorMsg}`);
    } else if (error.status === 404) {
      alert('File or endpoint not found. Please check the path and ensure the API is running.');
    } else if (error.status === 500) {
      const errorMsg = error.error?.detail || error.error?.error || 'Internal server error';
      alert(`Server error: ${errorMsg}`);
    } else {
      alert(`Error ${error.status}: ${error.message}`);
    }
  }

  private calculateSeverity(riskScore: number): 'Low' | 'Medium' | 'High' | 'Critical' {
    if (riskScore >= 80) {
      return 'Critical';
    } else if (riskScore >= 60) {
      return 'High';
    } else if (riskScore >= 30) {
      return 'Medium';
    } else {
      return 'Low';
    }
  }

  private formatStreamDetails(stream: StreamData): string {
    let details = '';
    
    details += `Name: ${stream.name}\n`;
    details += `Type: ${stream.stream_type}\n`;
    details += `Size: ${this.formatSize(stream.size_bytes)}\n`;
    details += `Risk Score: ${stream.risk_score}/100\n`;
    
    if (stream.is_executable !== undefined) {
      details += `Executable: ${stream.is_executable ? 'Yes' : 'No'}\n`;
    }
    
    if (stream.is_encrypted !== undefined) {
      details += `Encrypted: ${stream.is_encrypted ? 'Yes' : 'No'}\n`;
    }
    
    if (stream.entropy !== undefined) {
      details += `Entropy: ${stream.entropy.toFixed(2)}\n`;
    }
    
    if (stream.hash_md5) {
      details += `MD5: ${stream.hash_md5}\n`;
    }
    
    if (stream.hash_sha256) {
      details += `SHA256: ${stream.hash_sha256}\n`;
    }
    
    if (stream.creation_time) {
      details += `Created: ${new Date(stream.creation_time).toLocaleString()}\n`;
    }
    
    if (stream.modification_time) {
      details += `Modified: ${new Date(stream.modification_time).toLocaleString()}\n`;
    }
    
    return details;
  }

  selectAllDetectors(event: Event): void {
    const isChecked = (event.target as HTMLInputElement).checked;
    if (isChecked) {
      this.selectedDetectors = this.availableDetectors.map(detector => detector.value);
      // If ADS is selected, also select default methods
      if (this.isADSSelected()) {
        this.selectedADSMethods = ['powershell'];
      }
    } else {
      this.selectedDetectors = [];
      this.selectedADSMethods = [];
    }
  }

  selectAllADSMethods(event: Event): void {
    const isChecked = (event.target as HTMLInputElement).checked;
    if (isChecked) {
      const adsDetector = this.availableDetectors.find(d => d.value === 'ads_detector');
      if (adsDetector?.subOptions) {
        this.selectedADSMethods = adsDetector.subOptions.map(opt => opt.value);
      }
    } else {
      this.selectedADSMethods = [];
    }
  }

  isAllSelected(): boolean {
    return this.selectedDetectors.length === this.availableDetectors.length && 
           this.availableDetectors.length > 0;
  }

  isAllADSMethodsSelected(): boolean {
    const adsDetector = this.availableDetectors.find(d => d.value === 'ads_detector');
    return adsDetector?.subOptions ? 
           this.selectedADSMethods.length === adsDetector.subOptions.length : false;
  }

  // Test backend connection
  testBackendConnection(): void {
    this.http.get<{status: string, service: string}>(`${this.API_BASE_URL}/health`).subscribe({
      next: (response) => {
        alert(`✅ Backend is ${response.status} (${response.service})`);
      },
      error: (error: HttpErrorResponse) => {
        if (error.status === 0) {
          alert('❌ Cannot connect to backend. Make sure Flask server is running on port 5000.');
        } else {
          alert(`❌ Backend error: ${error.message}`);
        }
      }
    });
  }

  // Test ADS creation
  createTestADS(): void {
    this.http.get<ApiResponse>(`${this.API_BASE_URL}/test/create`).subscribe({
      next: (response) => {
        if (response.success) {
          alert(`✅ ${response.message}`);
        } else {
          const errorMsg = response.detail || response.error || 'Unknown error';
          alert(`❌ Failed to create test ADS: ${errorMsg}`);
        }
      },
      error: (error: HttpErrorResponse) => {
        alert(`❌ Error creating test ADS: ${error.message}`);
      }
    });
  }

  // Get directory statistics
  getDirectoryStats(): void {
    if (!this.analysisPath.trim()) {
      alert('Please enter a directory path first.');
      return;
    }
    
    this.http.get<ApiResponse>(`${this.API_BASE_URL}/stats?directory=${encodeURIComponent(this.analysisPath.trim())}`).subscribe({
      next: (response) => {
        if (response.success && response.data?.scan_summary) {
          const scanSummary = response.data.scan_summary;
          alert(`Directory Scan Results:\n\n` +
                `Total Files Scanned: ${scanSummary.total_files_scanned}\n` +
                `Files with ADS: ${scanSummary.files_with_ads}\n` +
                `Total ADS Streams: ${scanSummary.total_ads_streams}`);
        } else {
          const errorMsg = response.detail || response.error || 'Unknown error';
          alert(`❌ Failed to get directory stats: ${errorMsg}`);
        }
      },
      error: (error: HttpErrorResponse) => {
        alert(`❌ Error getting directory stats: ${error.message}`);
      }
    });
  }

  generateReport(): void {
    if (this.analysisResults.length === 0) {
      alert('No analysis results to generate a report from.');
      return;
    }

    const report = this.createReport();
    console.log('Report generated:', report);
    this.downloadReport(report);
  }

  private createReport(): string {
    const timestamp = new Date().toISOString();
    const target = this.selectedFile ? this.selectedFile.name : this.analysisPath;
    
    let report = `=== ANTI-FORENSICS ANALYSIS REPORT ===\n\n`;
    report += `Generated: ${timestamp}\n`;
    report += `Target: ${target}\n`;
    report += `Platform: ${navigator.platform}\n`;
    report += `Detectors Used: ${this.selectedDetectors.join(', ')}\n`;
    if (this.isADSSelected()) {
      report += `ADS Methods: ${this.selectedADSMethods.join(', ')}\n`;
    }
    report += `Scan Type: ${this.isScanningDirectory ? 'Directory Scan' : 'File Scan'}\n`;
    report += `Timestamp: ${new Date().toLocaleString()}\n\n`;
    
    if (this.summary) {
      report += `SUMMARY:\n`;
      report += `${this.summary}\n\n`;
    }
    
    if (this.riskAssessment) {
      report += `RISK ASSESSMENT:\n`;
      report += `  Level: ${this.riskAssessment.risk_level.toUpperCase()}\n`;
      report += `  Score: ${this.riskAssessment.score}/100\n`;
      report += `  Description: ${this.riskAssessment.description}\n`;
      
      if (this.riskAssessment.details) {
        const details = this.riskAssessment.details;
        report += `  Details:\n`;
        report += `    Total Streams: ${details.total_streams}\n`;
        report += `    Critical: ${details.critical_streams}\n`;
        report += `    High Risk: ${details.high_risk_streams}\n`;
        report += `    Medium Risk: ${details.medium_risk_streams}\n`;
        report += `    Low Risk: ${details.low_risk_streams}\n`;
        report += `    Executable: ${details.executable_streams}\n`;
        report += `    Encrypted: ${details.encrypted_streams}\n`;
        report += `    Total Size: ${details.total_size_human}\n`;
      }
      report += `\n`;
    }
    
    if (this.recommendations.length > 0) {
      report += `RECOMMENDATIONS:\n`;
      this.recommendations.forEach(rec => report += `  • ${rec}\n`);
      report += `\n`;
    }
    
    report += `DETAILED FINDINGS (${this.analysisResults.length} total):\n`;
    report += `-`.repeat(80) + `\n`;
    
    this.analysisResults.forEach((result, index) => {
      report += `FINDING #${index + 1}\n`;
      report += `Indicator: ${result.indicator}\n`;
      report += `Severity: ${result.severity}\n`;
      report += `Confidence: ${result.confidence}%\n`;
      report += `Description: ${result.description}\n`;
      
      if (result.content_preview) {
        report += `Content Preview: ${result.content_preview}\n`;
      }
      
      report += `Details:\n${result.details}\n`;
      report += `-`.repeat(80) + `\n`;
    });
    
    report += `\n=== END OF REPORT ===\n`;
    return report;
  }

  private downloadReport(reportContent: string): void {
    const blob = new Blob([reportContent], { type: 'text/plain;charset=utf-8' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
    const targetName = this.selectedFile ? 
      this.selectedFile.name.replace(/\.[^/.]+$/, "") : 
      this.analysisPath.replace(/[^a-z0-9]/gi, '_').slice(0, 50);
    const filename = `anti-forensics-report-${targetName}-${timestamp}.txt`;
    
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    window.URL.revokeObjectURL(url);
    
    alert(`Report '${filename}' has been downloaded.`);
  }

  // Helper method to display risk level with color
  getSeverityClass(severity: string): string {
    switch (severity.toLowerCase()) {
      case 'critical': return 'severity-critical';
      case 'high': return 'severity-high';
      case 'medium': return 'severity-medium';
      case 'low': return 'severity-low';
      default: return '';
    }
  }
}