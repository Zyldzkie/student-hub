# Student Hub

Ruby project setup.

## Setup (Windows)

### Option 1: RubyInstaller (Recommended for Windows)

1. **Download and Install Ruby:**
   - Go to [RubyInstaller.org](https://rubyinstaller.org/)
   - Download Ruby+Devkit 3.2.x (or latest version)
   - Run the installer and follow the prompts
   - **Important:** When prompted, check "Run 'ridk install' to setup MSYS2 and development toolchain"
   - After installation, open a new PowerShell/Command Prompt window

2. **Verify Ruby Installation:**
   ```powershell
   ruby --version
   ```

3. **Install Bundler:**
   ```powershell
   gem install bundler
   ```

4. **Install Project Dependencies:**
   ```powershell
   bundle install
   ```

### Option 2: Using Chocolatey

If you have Chocolatey installed:

```powershell
choco install ruby
gem install bundler
bundle install
```

### Option 3: Using WSL (Windows Subsystem for Linux)

If you prefer a Linux-like environment:

1. Install WSL2 and a Linux distribution (Ubuntu recommended)
2. Inside WSL, install Ruby:
   ```bash
   sudo apt update
   sudo apt install ruby-full ruby-dev build-essential
   ```
3. Install Bundler:
   ```bash
   gem install bundler
   ```
4. Install dependencies:
   ```bash
   bundle install
   ```

## Running the Application

After installing dependencies, start the web server:

```powershell
ruby app.rb
```

Or using Bundler:

```powershell
bundle exec ruby app.rb
```

The application will be available at `http://localhost:4567`

Open your web browser and navigate to that URL to see the StudentHub interface.

## Features

- **Dashboard**: Overview of your academic progress, GPA, active classes, pending tasks, and study hours
- **Grade Calculator**: Add classes and assignments, track grades, and calculate weighted averages
- **To-Do List**: Manage your tasks with filtering (All/Active/Completed)
- **Study Logger**: Log study sessions and track your study time

## Project Structure

```
student-hub/
├── app.rb              # Main Sinatra application
├── Gemfile             # Ruby dependencies
├── views/              # ERB templates
│   ├── layout.erb      # Main layout with sidebar
│   ├── dashboard.erb
│   ├── grade_calculator.erb
│   ├── todo_list.erb
│   └── study_logger.erb
└── public/             # Static assets
    ├── css/
    │   └── style.css   # Main stylesheet
    └── js/
        └── app.js      # Global JavaScript
```

## Troubleshooting

- **If `gem install` fails:** Make sure you installed Ruby+Devkit (not just Ruby) from RubyInstaller
- **If you see SSL errors:** Run `ridk install` in PowerShell to set up the development toolchain
- **If bundler commands fail:** Try running PowerShell as Administrator
- **If the server won't start:** Make sure port 4567 is not in use by another application

