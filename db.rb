require 'sqlite3'
require 'bcrypt'

class Database
  def self.init
    db = SQLite3::Database.new('student_hub.db')
    db.results_as_hash = true
    
    # Create users table
    db.execute <<-SQL
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        active_profile_id INTEGER,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    SQL
    
    # Create semester_profiles table
    db.execute <<-SQL
      CREATE TABLE IF NOT EXISTS semester_profiles (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        start_date TEXT,
        end_date TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )
    SQL
    
    # Create classes table
    db.execute <<-SQL
      CREATE TABLE IF NOT EXISTS classes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        profile_id INTEGER,
        name TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (profile_id) REFERENCES semester_profiles(id) ON DELETE CASCADE
      )
    SQL
    
    # Create assignments table
    db.execute <<-SQL
      CREATE TABLE IF NOT EXISTS assignments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        class_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        weight REAL NOT NULL,
        score REAL DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (class_id) REFERENCES classes(id) ON DELETE CASCADE
      )
    SQL
    
    # Create todos table
    db.execute <<-SQL
      CREATE TABLE IF NOT EXISTS todos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        profile_id INTEGER,
        title TEXT NOT NULL,
        description TEXT,
        due_date TEXT,
        completed BOOLEAN DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (profile_id) REFERENCES semester_profiles(id) ON DELETE CASCADE
      )
    SQL
    
    # Create study_sessions table
    db.execute <<-SQL
      CREATE TABLE IF NOT EXISTS study_sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        profile_id INTEGER,
        subject TEXT NOT NULL,
        hours REAL NOT NULL,
        notes TEXT,
        date TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (profile_id) REFERENCES semester_profiles(id) ON DELETE CASCADE
      )
    SQL
    
    # Create indexes for better performance
    db.execute "CREATE INDEX IF NOT EXISTS idx_classes_user_id ON classes(user_id)"
    db.execute "CREATE INDEX IF NOT EXISTS idx_classes_profile_id ON classes(profile_id)"
    db.execute "CREATE INDEX IF NOT EXISTS idx_assignments_class_id ON assignments(class_id)"
    db.execute "CREATE INDEX IF NOT EXISTS idx_todos_user_id ON todos(user_id)"
    db.execute "CREATE INDEX IF NOT EXISTS idx_todos_profile_id ON todos(profile_id)"
    db.execute "CREATE INDEX IF NOT EXISTS idx_study_sessions_user_id ON study_sessions(user_id)"
    db.execute "CREATE INDEX IF NOT EXISTS idx_study_sessions_profile_id ON study_sessions(profile_id)"
    db.execute "CREATE INDEX IF NOT EXISTS idx_semester_profiles_user_id ON semester_profiles(user_id)"
    
    # Migration: Create default profile for existing users without active_profile_id
    migrate_existing_data(db)
    
    db
  end
  
  def self.migrate_existing_data(db)
    # Get users without active_profile_id
    users_without_profile = db.execute("SELECT id FROM users WHERE active_profile_id IS NULL")
    
    users_without_profile.each do |user|
      user_id = user['id']
      
      # Check if user already has a profile
      existing_profile = db.execute("SELECT id FROM semester_profiles WHERE user_id = ?", user_id).first
      
      if existing_profile.nil?
        # Create default profile for this user
        db.execute("INSERT INTO semester_profiles (user_id, name, start_date) VALUES (?, ?, ?)",
                   user_id, "Default", Time.now.strftime('%Y-%m-%d'))
        profile_id = db.last_insert_row_id
        
        # Update user's active_profile_id
        db.execute("UPDATE users SET active_profile_id = ? WHERE id = ?", profile_id, user_id)
        
        # Migrate existing data to this profile
        db.execute("UPDATE classes SET profile_id = ? WHERE user_id = ? AND profile_id IS NULL", 
                   profile_id, user_id)
        db.execute("UPDATE todos SET profile_id = ? WHERE user_id = ? AND profile_id IS NULL", 
                   profile_id, user_id)
        db.execute("UPDATE study_sessions SET profile_id = ? WHERE user_id = ? AND profile_id IS NULL", 
                   profile_id, user_id)
      else
        # User has a profile, just set it as active
        db.execute("UPDATE users SET active_profile_id = ? WHERE id = ?", existing_profile['id'], user_id)
      end
    end
  end
  
  def self.get_db
    @db ||= init
  end
end

