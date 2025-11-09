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
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    SQL
    
    # Create classes table
    db.execute <<-SQL
      CREATE TABLE IF NOT EXISTS classes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
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
        title TEXT NOT NULL,
        description TEXT,
        due_date TEXT,
        completed BOOLEAN DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )
    SQL
    
    # Create study_sessions table
    db.execute <<-SQL
      CREATE TABLE IF NOT EXISTS study_sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        subject TEXT NOT NULL,
        hours REAL NOT NULL,
        notes TEXT,
        date TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )
    SQL
    
    # Create indexes for better performance
    db.execute "CREATE INDEX IF NOT EXISTS idx_classes_user_id ON classes(user_id)"
    db.execute "CREATE INDEX IF NOT EXISTS idx_assignments_class_id ON assignments(class_id)"
    db.execute "CREATE INDEX IF NOT EXISTS idx_todos_user_id ON todos(user_id)"
    db.execute "CREATE INDEX IF NOT EXISTS idx_study_sessions_user_id ON study_sessions(user_id)"
    
    db
  end
  
  def self.get_db
    @db ||= init
  end
end

