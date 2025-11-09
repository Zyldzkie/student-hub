require 'sinatra'
require 'json'
require 'securerandom'
require_relative 'db'
require 'bcrypt'

# Enable sessions for storing user login state
enable :sessions
# Session secret must be exactly 32 bytes (256 bits)
if ENV['SESSION_SECRET']
  set :session_secret, ENV['SESSION_SECRET']
else
  # Decode hex string to get 32 bytes
  set :session_secret, '72ef8a49f5e04fbe422d93bde0e6882ac4af6073dfa978799445777c8fbd6838' # Don't change this
end

# Set public folder for static assets
set :public_folder, File.dirname(__FILE__) + '/public'

# Set views directory
set :views, File.dirname(__FILE__) + '/views'

# Configure server
set :port, 4567
set :bind, '0.0.0.0'

# Initialize database
Database.init

# Helper methods
helpers do
  def current_user
    @current_user ||= session[:user_id] ? get_user_by_id(session[:user_id]) : nil
  end

  def logged_in?
    !current_user.nil?
  end

  def require_login
    redirect '/login' unless logged_in?
  end

  def get_user_by_id(id)
    db = Database.get_db
    user = db.execute("SELECT * FROM users WHERE id = ?", id).first
    user
  end

  def get_user_by_username(username)
    db = Database.get_db
    user = db.execute("SELECT * FROM users WHERE username = ?", username).first
    user
  end
  
  def active_profile_id
    current_user ? current_user['active_profile_id'] : nil
  end
end

# Authentication routes
get '/login' do
  redirect '/dashboard' if logged_in?
  erb :login, :layout => false
end

post '/login' do
  username = params[:username]
  password = params[:password]

  user = get_user_by_username(username)
  
  if user && BCrypt::Password.new(user['password_hash']) == password
    session[:user_id] = user['id']
    redirect '/dashboard'
  else
    @error = 'Invalid username or password'
    erb :login, :layout => false
  end
end

get '/register' do
  redirect '/dashboard' if logged_in?
  erb :register, :layout => false
end

post '/register' do
  username = params[:username]
  email = params[:email]
  password = params[:password]
  password_confirm = params[:password_confirm]

  # Validation
  if password != password_confirm
    @error = 'Passwords do not match'
    return erb :register, :layout => false
  end

  if password.length < 6
    @error = 'Password must be at least 6 characters'
    return erb :register, :layout => false
  end

  db = Database.get_db
  
  # Check if username or email already exists
  existing_user = db.execute("SELECT * FROM users WHERE username = ? OR email = ?", username, email).first
  if existing_user
    @error = 'Username or email already exists'
    return erb :register, :layout => false
  end

  # Create user
  password_hash = BCrypt::Password.create(password)
  db.execute("INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)", 
             username, email, password_hash)
  
  user = get_user_by_username(username)
  user_id = user['id']
  
  # Create default profile for new user
  db.execute("INSERT INTO semester_profiles (user_id, name, start_date) VALUES (?, ?, ?)",
             user_id, "Default", Time.now.strftime('%Y-%m-%d'))
  profile_id = db.last_insert_row_id
  
  # Set as active profile
  db.execute("UPDATE users SET active_profile_id = ? WHERE id = ?", profile_id, user_id)
  
  session[:user_id] = user_id
  redirect '/dashboard'
end

post '/logout' do
  session.clear
  redirect '/login'
end

# Protected routes - require login
before do
  protected_paths = ['/dashboard', '/grade-calculator', '/todo-list', '/study-logger', '/notes']
  api_path = request.path.start_with?('/api/')
  
  if protected_paths.include?(request.path) || api_path
    require_login unless request.path == '/api/login' || request.path == '/api/register'
  end
end

# Home route - redirects to dashboard or login
get '/' do
  if logged_in?
    redirect '/dashboard'
  else
    redirect '/login'
  end
end

# Dashboard route
get '/dashboard' do
  erb :dashboard
end

# Grade Calculator route
get '/grade-calculator' do
  erb :grade_calculator
end

# Todo List route
get '/todo-list' do
  erb :todo_list
end

# Study Logger route
get '/study-logger' do
  erb :study_logger
end

get '/notes' do
  erb :notes
end

# API routes for GWA Calculator
get '/api/gwa-subjects' do
  content_type :json
  { subjects: get_user_gwa_subjects, gwa: calculate_gwa }.to_json
end

post '/api/gwa-subjects' do
  content_type :json
  db = Database.get_db
  data = JSON.parse(request.body.read)
  
  db.execute("INSERT INTO gwa_subjects (user_id, profile_id, subject_name, units, grade) VALUES (?, ?, ?, ?, ?)", 
             current_user['id'], active_profile_id, data['subject_name'], data['units'], data['grade'])
  
  { success: true, subjects: get_user_gwa_subjects, gwa: calculate_gwa }.to_json
end

put '/api/gwa-subjects/:id' do
  content_type :json
  db = Database.get_db
  id = params[:id].to_i
  data = JSON.parse(request.body.read)
  
  # Verify subject belongs to user
  subject = db.execute("SELECT * FROM gwa_subjects WHERE id = ? AND user_id = ?", 
                       id, current_user['id']).first
  return { success: false, error: 'Subject not found' }.to_json unless subject
  
  updates = []
  values = []
  
  if data['subject_name']
    updates << "subject_name = ?"
    values << data['subject_name']
  end
  
  if data.key?('units')
    updates << "units = ?"
    values << data['units']
  end
  
  if data.key?('grade')
    updates << "grade = ?"
    values << (data['grade'] ? data['grade'] : nil)
  end
  
  values << id
  values << current_user['id']
  
  db.execute("UPDATE gwa_subjects SET #{updates.join(', ')} WHERE id = ? AND user_id = ?", *values)
  
  { success: true, subjects: get_user_gwa_subjects, gwa: calculate_gwa }.to_json
end

delete '/api/gwa-subjects/:id' do
  content_type :json
  db = Database.get_db
  id = params[:id].to_i
  
  db.execute("DELETE FROM gwa_subjects WHERE id = ? AND user_id = ?", 
             id, current_user['id'])
  
  { success: true, subjects: get_user_gwa_subjects, gwa: calculate_gwa }.to_json
end

# API routes for Todo List
get '/api/todos' do
  content_type :json
  { todos: get_user_todos }.to_json
end

post '/api/todos' do
  content_type :json
  db = Database.get_db
  data = JSON.parse(request.body.read)
  
  db.execute("INSERT INTO todos (user_id, profile_id, title, description, due_date, priority, completed) VALUES (?, ?, ?, ?, ?, ?, ?)",
             current_user['id'], active_profile_id, data['title'], data['description'], data['due_date'], data['priority'] || 'medium', 0)
  
  { success: true, todos: get_user_todos }.to_json
end

put '/api/todos/:id' do
  content_type :json
  db = Database.get_db
  id = params[:id].to_i
  data = JSON.parse(request.body.read)
  
  updates = []
  values = []
  
  if data.key?('completed')
    updates << "completed = ?"
    values << (data['completed'] ? 1 : 0)
  end
  
  if data['title']
    updates << "title = ?"
    values << data['title']
  end
  
  if data['description']
    updates << "description = ?"
    values << data['description']
  end
  
  if data['due_date']
    updates << "due_date = ?"
    values << data['due_date']
  end
  
  if data['priority']
    updates << "priority = ?"
    values << data['priority']
  end
  
  values << id
  values << current_user['id']
  
  db.execute("UPDATE todos SET #{updates.join(', ')} WHERE id = ? AND user_id = ?", *values)
  
  { success: true, todos: get_user_todos }.to_json
end

delete '/api/todos/:id' do
  content_type :json
  db = Database.get_db
  id = params[:id].to_i
  
  db.execute("DELETE FROM todos WHERE id = ? AND user_id = ?", id, current_user['id'])
  
  { success: true, todos: get_user_todos }.to_json
end

# API routes for Study Logger
get '/api/study-sessions' do
  content_type :json
  { sessions: get_user_study_sessions }.to_json
end

post '/api/study-sessions' do
  content_type :json
  db = Database.get_db
  data = JSON.parse(request.body.read)
  
  date = data['date'] || Time.now.strftime('%Y-%m-%d')
  db.execute("INSERT INTO study_sessions (user_id, profile_id, subject, hours, notes, date) VALUES (?, ?, ?, ?, ?, ?)",
             current_user['id'], active_profile_id, data['subject'], data['hours'], data['notes'], date)
  
  { success: true, sessions: get_user_study_sessions }.to_json
end

delete '/api/study-sessions/:id' do
  content_type :json
  db = Database.get_db
  id = params[:id].to_i
  
  db.execute("DELETE FROM study_sessions WHERE id = ? AND user_id = ?", id, current_user['id'])
  
  { success: true, sessions: get_user_study_sessions }.to_json
end

# API routes for Notes
get '/api/notes' do
  content_type :json
  { notes: get_user_notes }.to_json
end

post '/api/notes' do
  content_type :json
  db = Database.get_db
  data = JSON.parse(request.body.read)
  
  db.execute("INSERT INTO notes (user_id, profile_id, title, content, updated_at) VALUES (?, ?, ?, ?, ?)",
             current_user['id'], active_profile_id, data['title'], data['content'], Time.now.to_s)
  
  { success: true, notes: get_user_notes }.to_json
end

put '/api/notes/:id' do
  content_type :json
  db = Database.get_db
  id = params[:id].to_i
  data = JSON.parse(request.body.read)
  
  # Verify note belongs to user
  note = db.execute("SELECT * FROM notes WHERE id = ? AND user_id = ?", 
                   id, current_user['id']).first
  return { success: false, error: 'Note not found' }.to_json unless note
  
  updates = []
  values = []
  
  if data['title']
    updates << "title = ?"
    values << data['title']
  end
  
  if data['content']
    updates << "content = ?"
    values << data['content']
  end
  
  updates << "updated_at = ?"
  values << Time.now.to_s
  values << id
  values << current_user['id']
  
  db.execute("UPDATE notes SET #{updates.join(', ')} WHERE id = ? AND user_id = ?", *values)
  
  { success: true, notes: get_user_notes }.to_json
end

delete '/api/notes/:id' do
  content_type :json
  db = Database.get_db
  id = params[:id].to_i
  
  db.execute("DELETE FROM notes WHERE id = ? AND user_id = ?", id, current_user['id'])
  
  { success: true, notes: get_user_notes }.to_json
end

# API route for Recent Activity
get '/api/recent-activity' do
  content_type :json
  { activities: get_recent_activities }.to_json
end

# API routes for Semester Profiles
get '/api/profiles' do
  content_type :json
  { profiles: get_user_profiles, active_profile_id: active_profile_id }.to_json
end

post '/api/profiles' do
  content_type :json
  db = Database.get_db
  data = JSON.parse(request.body.read)
  
  db.execute("INSERT INTO semester_profiles (user_id, name, start_date, end_date) VALUES (?, ?, ?, ?)",
             current_user['id'], data['name'], data['start_date'] || nil, data['end_date'] || nil)
  
  profile_id = db.last_insert_row_id
  
  # If this is the first profile, make it active
  if current_user['active_profile_id'].nil?
    db.execute("UPDATE users SET active_profile_id = ? WHERE id = ?", profile_id, current_user['id'])
    @current_user = nil # Clear cache
  end
  
  { success: true, profiles: get_user_profiles, active_profile_id: active_profile_id }.to_json
end

put '/api/profiles/:id/activate' do
  content_type :json
  db = Database.get_db
  profile_id = params[:id].to_i
  
  # Verify profile belongs to user
  profile = db.execute("SELECT * FROM semester_profiles WHERE id = ? AND user_id = ?", 
                       profile_id, current_user['id']).first
  return { success: false, error: 'Profile not found' }.to_json unless profile
  
  db.execute("UPDATE users SET active_profile_id = ? WHERE id = ?", profile_id, current_user['id'])
  @current_user = nil # Clear cache
  
  { success: true, profiles: get_user_profiles, active_profile_id: profile_id }.to_json
end

delete '/api/profiles/:id' do
  content_type :json
  db = Database.get_db
  profile_id = params[:id].to_i
  
  # Verify profile belongs to user
  profile = db.execute("SELECT * FROM semester_profiles WHERE id = ? AND user_id = ?", 
                       profile_id, current_user['id']).first
  return { success: false, error: 'Profile not found' }.to_json unless profile
  
  # Can't delete if it's the only profile
  all_profiles = get_user_profiles
  if all_profiles.length <= 1
    return { success: false, error: 'Cannot delete your only profile' }.to_json
  end
  
  # If deleting active profile, switch to another one
  if current_user['active_profile_id'] == profile_id
    new_active = all_profiles.find { |p| p['id'] != profile_id }
    db.execute("UPDATE users SET active_profile_id = ? WHERE id = ?", new_active['id'], current_user['id'])
    @current_user = nil # Clear cache
  end
  
  db.execute("DELETE FROM semester_profiles WHERE id = ? AND user_id = ?", profile_id, current_user['id'])
  
  { success: true, profiles: get_user_profiles, active_profile_id: active_profile_id }.to_json
end

get '/api/profiles/:id/analytics' do
  content_type :json
  profile_id = params[:id].to_i
  
  # Verify profile belongs to user
  db = Database.get_db
  profile = db.execute("SELECT * FROM semester_profiles WHERE id = ? AND user_id = ?", 
                       profile_id, current_user['id']).first
  return { success: false, error: 'Profile not found' }.to_json unless profile
  
  analytics = get_profile_analytics(profile_id)
  { success: true, analytics: analytics, profile: profile }.to_json
end

# Helper methods for database queries
def get_user_gwa_subjects
  db = Database.get_db
  subjects = db.execute("SELECT * FROM gwa_subjects WHERE user_id = ? AND profile_id = ? ORDER BY created_at DESC", 
                        current_user['id'], active_profile_id)
  subjects.map { |s|
    {
      'id' => s['id'],
      'subject_name' => s['subject_name'],
      'units' => s['units'],
      'grade' => s['grade'],
      'created_at' => s['created_at']
    }
  }
end

def calculate_gwa
  subjects = get_user_gwa_subjects
  return nil if subjects.empty?
  
  total_units = 0
  total_weighted_grade = 0
  
  subjects.each do |subject|
    units = subject['units'] || 0
    grade = subject['grade']
    
    if grade && grade > 0
      total_units += units
      total_weighted_grade += grade * units
    end
  end
  
  return nil if total_units == 0
  (total_weighted_grade / total_units).round(2)
end

def get_user_todos
  db = Database.get_db
  todos = db.execute("SELECT * FROM todos WHERE user_id = ? AND profile_id = ? ORDER BY created_at DESC", 
                     current_user['id'], active_profile_id)
  todos.map { |t| 
    {
      'id' => t['id'],
      'title' => t['title'],
      'description' => t['description'],
      'due_date' => t['due_date'],
      'priority' => t['priority'] || 'medium',
      'completed' => t['completed'] == 1
    }
  }
end

def get_user_study_sessions
  db = Database.get_db
  sessions = db.execute("SELECT * FROM study_sessions WHERE user_id = ? AND profile_id = ? ORDER BY date DESC, created_at DESC", 
                        current_user['id'], active_profile_id)
  sessions.map { |s|
    {
      'id' => s['id'],
      'subject' => s['subject'],
      'hours' => s['hours'],
      'notes' => s['notes'],
      'date' => s['date']
    }
  }
end

def get_user_notes
  db = Database.get_db
  notes = db.execute("SELECT * FROM notes WHERE user_id = ? AND profile_id = ? ORDER BY updated_at DESC", 
                     current_user['id'], active_profile_id)
  notes.map { |n|
    {
      'id' => n['id'],
      'title' => n['title'],
      'content' => n['content'],
      'created_at' => n['created_at'],
      'updated_at' => n['updated_at']
    }
  }
end

def get_user_profiles
  db = Database.get_db
  profiles = db.execute("SELECT * FROM semester_profiles WHERE user_id = ? ORDER BY created_at DESC", 
                        current_user['id'])
  profiles.map { |p|
    {
      'id' => p['id'],
      'name' => p['name'],
      'start_date' => p['start_date'],
      'end_date' => p['end_date'],
      'created_at' => p['created_at']
    }
  }
end

def get_recent_activities
  db = Database.get_db
  activities = []
  
  # Get recent GWA subjects (last 10)
  subjects = db.execute("SELECT * FROM gwa_subjects WHERE user_id = ? AND profile_id = ? ORDER BY created_at DESC LIMIT 10", 
                       current_user['id'], active_profile_id)
  subjects.each do |subject|
    activities << {
      'type' => 'gwa_subject',
      'action' => 'added',
      'description' => "Added subject: #{subject['subject_name']} (#{subject['units']} units)",
      'timestamp' => subject['created_at'],
      'icon' => 'fas fa-book'
    }
  end
  
  # Get recent todos (last 10)
  todos = db.execute("SELECT * FROM todos WHERE user_id = ? AND profile_id = ? ORDER BY created_at DESC LIMIT 10", 
                    current_user['id'], active_profile_id)
  todos.each do |todo|
    action = todo['completed'] == 1 ? 'completed' : 'created'
    activities << {
      'type' => 'todo',
      'action' => action,
      'description' => action == 'completed' ? "Completed task: #{todo['title']}" : "Created task: #{todo['title']}",
      'timestamp' => todo['created_at'],
      'icon' => action == 'completed' ? 'fas fa-check-circle' : 'fas fa-tasks'
    }
  end
  
  # Get recent study sessions (last 10)
  sessions = db.execute("SELECT * FROM study_sessions WHERE user_id = ? AND profile_id = ? ORDER BY created_at DESC LIMIT 10", 
                       current_user['id'], active_profile_id)
  sessions.each do |session|
    minutes = (session['hours'].to_f * 60).round
    activities << {
      'type' => 'study_session',
      'action' => 'completed',
      'description' => "Completed #{minutes} min study session: #{session['subject']}",
      'timestamp' => session['created_at'],
      'icon' => 'fas fa-book-open'
    }
  end
  
  # Get recent notes (last 10)
  notes = db.execute("SELECT * FROM notes WHERE user_id = ? AND profile_id = ? ORDER BY updated_at DESC LIMIT 10", 
                    current_user['id'], active_profile_id)
  notes.each do |note|
    action = note['updated_at'] != note['created_at'] ? 'updated' : 'created'
    activities << {
      'type' => 'note',
      'action' => action,
      'description' => action == 'updated' ? "Updated note: #{note['title']}" : "Created note: #{note['title']}",
      'timestamp' => note['updated_at'],
      'icon' => 'fas fa-sticky-note'
    }
  end
  
  # Sort by timestamp (newest first) and limit to 20 most recent
  activities.sort_by { |a| a['timestamp'] }.reverse.first(20)
end

def get_profile_analytics(profile_id)
  db = Database.get_db
  
  # Get GWA subjects count and GWA
  subjects = db.execute("SELECT * FROM gwa_subjects WHERE user_id = ? AND profile_id = ?", 
                       current_user['id'], profile_id)
  
  total_units = 0
  total_weighted_grade = 0
  
  subjects.each do |subject|
    units = subject['units'] || 0
    grade = subject['grade']
    
    if grade && grade > 0
      total_units += units
      total_weighted_grade += grade * units
    end
  end
  
  gwa = total_units > 0 ? (total_weighted_grade / total_units).round(2) : nil
  
  # Get todos count
  todos = db.execute("SELECT * FROM todos WHERE user_id = ? AND profile_id = ?", 
                     current_user['id'], profile_id)
  completed_todos = todos.select { |t| t['completed'] == 1 }.length
  
  # Get study sessions total hours
  sessions = db.execute("SELECT SUM(hours) as total_hours FROM study_sessions WHERE user_id = ? AND profile_id = ?", 
                        current_user['id'], profile_id)
  total_study_hours = sessions.first['total_hours'] || 0
  
  {
    'subjects_count' => subjects.length,
    'gwa' => gwa,
    'todos_count' => todos.length,
    'completed_todos' => completed_todos,
    'total_study_hours' => total_study_hours.round(1)
  }
end
