import { Routes } from '@angular/router';
import { HomeComponent } from './pages/home/home';
import { DashboardComponent } from './pages/dashboard/dashboard';
import { EvidenceUploadComponent } from './pages/evidence-upload/evidence-upload';
import { FilesystemVisualizerComponent } from './pages/filesystem-visualizer/filesystem-visualizer';
import { AntiForensicsDetectorComponent } from './pages/anti-forensics-detector/anti-forensics-detector';
import { ReportGeneratorComponent } from './pages/report-generator/report-generator';

export const routes: Routes = [
  { path: '', redirectTo: '/home', pathMatch: 'full' },
  { path: 'home', component: HomeComponent },
  { path: 'dashboard', component: DashboardComponent },
  { path: 'evidence-upload', component: EvidenceUploadComponent },
  { path: 'filesystem-visualizer', component: FilesystemVisualizerComponent },
  { path: 'anti-forensics-detector', component: AntiForensicsDetectorComponent },
  { path: 'report-generator', component: ReportGeneratorComponent },
  { path: '**', redirectTo: '/home' } // Wildcard route for a 404 page
];