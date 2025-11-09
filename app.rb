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
end

# Authentication routes
get '/login' do
  redirect '/dashboard' if logged_in?
  erb :login
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
    erb :login
  end
end

get '/register' do
  redirect '/dashboard' if logged_in?
  erb :register
end

post '/register' do
  username = params[:username]
  email = params[:email]
  password = params[:password]
  password_confirm = params[:password_confirm]

  # Validation
  if password != password_confirm
    @error = 'Passwords do not match'
    return erb :register
  end

  if password.length < 6
    @error = 'Password must be at least 6 characters'
    return erb :register
  end

  db = Database.get_db
  
  # Check if username or email already exists
  existing_user = db.execute("SELECT * FROM users WHERE username = ? OR email = ?", username, email).first
  if existing_user
    @error = 'Username or email already exists'
    return erb :register
  end

  # Create user
  password_hash = BCrypt::Password.create(password)
  db.execute("INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)", 
             username, email, password_hash)
  
  user = get_user_by_username(username)
  session[:user_id] = user['id']
  redirect '/dashboard'
end

post '/logout' do
  session.clear
  redirect '/login'
end

# Protected routes - require login
before do
  protected_paths = ['/dashboard', '/grade-calculator', '/todo-list', '/study-logger']
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

# API routes for Grade Calculator
post '/api/classes' do
  content_type :json
  db = Database.get_db
  data = JSON.parse(request.body.read)
  
  db.execute("INSERT INTO classes (user_id, name) VALUES (?, ?)", 
             current_user['id'], data['name'])
  
  class_id = db.last_insert_row_id
  classes = get_user_classes
  { success: true, classes: classes }.to_json
end

get '/api/classes' do
  content_type :json
  { classes: get_user_classes }.to_json
end

delete '/api/classes/:id' do
  content_type :json
  db = Database.get_db
  db.execute("DELETE FROM classes WHERE id = ? AND user_id = ?", 
             params[:id], current_user['id'])
  { success: true, classes: get_user_classes }.to_json
end

post '/api/classes/:class_id/assignments' do
  content_type :json
  db = Database.get_db
  data = JSON.parse(request.body.read)
  class_id = params[:class_id].to_i
  
  # Verify class belongs to user
  class_record = db.execute("SELECT * FROM classes WHERE id = ? AND user_id = ?", 
                           class_id, current_user['id']).first
  return { success: false, error: 'Class not found' }.to_json unless class_record
  
  db.execute("INSERT INTO assignments (class_id, name, weight, score) VALUES (?, ?, ?, ?)",
             class_id, data['name'], data['weight'], data['score'] || 0)
  
  { success: true, classes: get_user_classes }.to_json
end

delete '/api/classes/:class_id/assignments/:assignment_id' do
  content_type :json
  db = Database.get_db
  class_id = params[:class_id].to_i
  assignment_id = params[:assignment_id].to_i
  
  # Verify class belongs to user
  class_record = db.execute("SELECT * FROM classes WHERE id = ? AND user_id = ?", 
                           class_id, current_user['id']).first
  return { success: false, error: 'Class not found' }.to_json unless class_record
  
  db.execute("DELETE FROM assignments WHERE id = ? AND class_id = ?", 
             assignment_id, class_id)
  
  { success: true, classes: get_user_classes }.to_json
end

put '/api/classes/:class_id/assignments/:assignment_id' do
  content_type :json
  db = Database.get_db
  class_id = params[:class_id].to_i
  assignment_id = params[:assignment_id].to_i
  data = JSON.parse(request.body.read)
  
  # Verify class belongs to user
  class_record = db.execute("SELECT * FROM classes WHERE id = ? AND user_id = ?", 
                           class_id, current_user['id']).first
  return { success: false, error: 'Class not found' }.to_json unless class_record
  
  if data['score']
    db.execute("UPDATE assignments SET score = ? WHERE id = ? AND class_id = ?",
               data['score'], assignment_id, class_id)
  end
  
  { success: true, classes: get_user_classes }.to_json
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
  
  db.execute("INSERT INTO todos (user_id, title, description, due_date, completed) VALUES (?, ?, ?, ?, ?)",
             current_user['id'], data['title'], data['description'], data['due_date'], 0)
  
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
  db.execute("INSERT INTO study_sessions (user_id, subject, hours, notes, date) VALUES (?, ?, ?, ?, ?)",
             current_user['id'], data['subject'], data['hours'], data['notes'], date)
  
  { success: true, sessions: get_user_study_sessions }.to_json
end

delete '/api/study-sessions/:id' do
  content_type :json
  db = Database.get_db
  id = params[:id].to_i
  
  db.execute("DELETE FROM study_sessions WHERE id = ? AND user_id = ?", id, current_user['id'])
  
  { success: true, sessions: get_user_study_sessions }.to_json
end

# Helper methods for database queries
def get_user_classes
  db = Database.get_db
  classes = db.execute("SELECT * FROM classes WHERE user_id = ? ORDER BY created_at DESC", 
                       current_user['id'])
  
  classes.map do |cls|
    assignments = db.execute("SELECT * FROM assignments WHERE class_id = ?", cls['id'])
    cls.merge('assignments' => assignments.map { |a| 
      {
        'id' => a['id'],
        'name' => a['name'],
        'weight' => a['weight'],
        'score' => a['score']
      }
    })
  end
end

def get_user_todos
  db = Database.get_db
  todos = db.execute("SELECT * FROM todos WHERE user_id = ? ORDER BY created_at DESC", 
                     current_user['id'])
  todos.map { |t| 
    {
      'id' => t['id'],
      'title' => t['title'],
      'description' => t['description'],
      'due_date' => t['due_date'],
      'completed' => t['completed'] == 1
    }
  }
end

def get_user_study_sessions
  db = Database.get_db
  sessions = db.execute("SELECT * FROM study_sessions WHERE user_id = ? ORDER BY date DESC, created_at DESC", 
                        current_user['id'])
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
