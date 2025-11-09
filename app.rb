require 'sinatra'
require 'json'
require 'securerandom'

# Enable sessions for storing data
enable :sessions
# Session secret must be exactly 32 bytes (256 bits)
# Using the provided hex-encoded 32-byte key (64 hex characters = 32 bytes)
if ENV['SESSION_SECRET']
  set :session_secret, ENV['SESSION_SECRET']
else
  # Decode hex string to get 32 bytes - using the key directly
  set :session_secret, '72ef8a49f5e04fbe422d93bde0e6882ac4af6073dfa978799445777c8fbd6838'
end

# Set public folder for static assets
set :public_folder, File.dirname(__FILE__) + '/public'

# Set views directory
set :views, File.dirname(__FILE__) + '/views'

# Configure server
set :port, 4567
set :bind, '0.0.0.0'

# Home route - redirects to dashboard
get '/' do
  redirect '/dashboard'
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
  session[:classes] ||= []
  data = JSON.parse(request.body.read)
  session[:classes] << data
  { success: true, classes: session[:classes] }.to_json
end

get '/api/classes' do
  content_type :json
  { classes: session[:classes] || [] }.to_json
end

delete '/api/classes/:id' do
  content_type :json
  session[:classes] ||= []
  session[:classes].delete_at(params[:id].to_i)
  { success: true, classes: session[:classes] }.to_json
end

post '/api/classes/:class_id/assignments' do
  content_type :json
  session[:classes] ||= []
  data = JSON.parse(request.body.read)
  class_id = params[:class_id].to_i
  session[:classes][class_id]['assignments'] ||= []
  session[:classes][class_id]['assignments'] << data
  { success: true, classes: session[:classes] }.to_json
end

delete '/api/classes/:class_id/assignments/:assignment_id' do
  content_type :json
  session[:classes] ||= []
  class_id = params[:class_id].to_i
  assignment_id = params[:assignment_id].to_i
  session[:classes][class_id]['assignments'].delete_at(assignment_id)
  { success: true, classes: session[:classes] }.to_json
end

put '/api/classes/:class_id/assignments/:assignment_id' do
  content_type :json
  session[:classes] ||= []
  class_id = params[:class_id].to_i
  assignment_id = params[:assignment_id].to_i
  data = JSON.parse(request.body.read)
  session[:classes][class_id]['assignments'][assignment_id].merge!(data)
  { success: true, classes: session[:classes] }.to_json
end

# API routes for Todo List
get '/api/todos' do
  content_type :json
  { todos: session[:todos] || [] }.to_json
end

post '/api/todos' do
  content_type :json
  session[:todos] ||= []
  data = JSON.parse(request.body.read)
  data['id'] = Time.now.to_i
  data['completed'] = false
  session[:todos] << data
  { success: true, todos: session[:todos] }.to_json
end

put '/api/todos/:id' do
  content_type :json
  session[:todos] ||= []
  id = params[:id].to_i
  data = JSON.parse(request.body.read)
  todo = session[:todos].find { |t| t['id'] == id }
  todo.merge!(data) if todo
  { success: true, todos: session[:todos] }.to_json
end

delete '/api/todos/:id' do
  content_type :json
  session[:todos] ||= []
  id = params[:id].to_i
  session[:todos].reject! { |t| t['id'] == id }
  { success: true, todos: session[:todos] }.to_json
end

# API routes for Study Logger
get '/api/study-sessions' do
  content_type :json
  { sessions: session[:study_sessions] || [] }.to_json
end

post '/api/study-sessions' do
  content_type :json
  session[:study_sessions] ||= []
  data = JSON.parse(request.body.read)
  data['id'] = Time.now.to_i
  data['date'] = Time.now.strftime('%Y-%m-%d')
  session[:study_sessions] << data
  { success: true, sessions: session[:study_sessions] }.to_json
end

delete '/api/study-sessions/:id' do
  content_type :json
  session[:study_sessions] ||= []
  id = params[:id].to_i
  session[:study_sessions].reject! { |s| s['id'] == id }
  { success: true, sessions: session[:study_sessions] }.to_json
end

