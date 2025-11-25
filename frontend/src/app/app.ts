import { Component, signal } from '@angular/core';
import { NavbarComponent } from './components/navbar/navbar';
import { FooterComponent } from './components/footer/footer';
import { RouterModule } from '@angular/router';
import { CommonModule } from '@angular/common';
import { routes } from './app.routes';

@Component({
  selector: 'app-root',
  templateUrl: './app.html',
  standalone: true,
  styleUrl: './app.scss',
  imports: [
    NavbarComponent,
    FooterComponent,
    CommonModule,
    RouterModule
  ]
})
export class App {
  protected readonly title = signal('frontend');
}
