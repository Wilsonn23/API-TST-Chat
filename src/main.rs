use serde::{Deserialize, Serialize};
use sqlx::sqlite::SqlitePool;
use sqlx::Row;
use tide::http::headers::HeaderValue;
use tide::security::CorsMiddleware;
use tide::{Request, Response, StatusCode};

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Serialize)]
struct LoginResponse {
    status: String,
    message: String,
}

#[derive(Deserialize)]
struct LogoutRequest {
    username: String,
}

#[derive(Serialize)]
struct LogoutResponse {
    status: String,
    message: String,
}

#[derive(Deserialize)]
struct RegisterRequest {
    username: String,
    password: String,
}

#[derive(Serialize)]
struct RegisterResponse {
    status: String,
    message: String,
}

#[derive(Serialize, sqlx::FromRow)]
struct Movie {
    id: i32,
    adult: bool,
    backdrop_path: Option<String>,
    genre_ids: String,
    origin_country: String,
    original_language: Option<String>,
    original_name: Option<String>,
    original_title: Option<String>,
    overview: Option<String>,
    popularity: f64,
    poster_path: Option<String>,
    first_air_date: Option<String>,
    release_date: Option<String>,
    name: Option<String>,
    title: Option<String>,
    video: bool,
    vote_average: f64,
    vote_count: i32,
}

#[derive(Serialize, sqlx::FromRow)]
struct ChatMessage {
    chat_id: i32,
    movie_id: i32,
    user_id: i64,
    username: String,
    chat: String,
    created_at: String,
}

#[derive(Deserialize)]
struct SendChatRequest {
    movie_id: i32,
    user_id: i64,
    chat: String,
}

#[derive(Serialize)]
struct ChatResponse {
    status: String,
    message: String,
}

#[async_std::main]
async fn main() -> tide::Result<()> {
    let pool = SqlitePool::connect("sqlite:./movies.db").await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            logged_in BOOLEAN NOT NULL DEFAULT 0
        )
        "#,
    )
    .execute(&pool)
    .await?;

    sqlx::query(
        r#"
            CREATE TABLE IF NOT EXISTS chats (
                chat_id INTEGER PRIMARY KEY AUTOINCREMENT,
                movie_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                chat TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (movie_id) REFERENCES movies(id)
            )
            "#,
    )
    .execute(&pool)
    .await?;

    let mut app = tide::with_state(pool);
    app.at("/movies").get(get_movies);

    app.at("/register").post(register);

    app.at("/login").post(login);

    app.at("/logout").post(logout);

    app.at("/chat").post(post_chat);

    app.at("/chat/:movie_id").get(get_chats);

    println!("Server running at http://0.0.0.0:8081");

    let cors = CorsMiddleware::new()
    .allow_methods("GET, POST, OPTIONS".parse::<HeaderValue>().unwrap())
    .allow_origin("*") // Mengizinkan semua akses untuk development
    .allow_credentials(false);

    app.with(cors);

    app.listen("0.0.0.0:8081").await?;
    Ok(())
}

async fn login(mut req: Request<SqlitePool>) -> tide::Result {
    let data: LoginRequest = req.body_json().await?;
    let pool = req.state();

    let row = sqlx::query(
        r#"
        SELECT id, password
        FROM users
        WHERE username = ?
        "#,
    )
    .bind(&data.username)
    .fetch_optional(pool)
    .await?;

    if row.is_none() {
        let mut res = Response::new(StatusCode::Unauthorized);
        res.set_body(tide::Body::from_json(&LoginResponse {
            status: "Failed".into(),
            message: "User tidak ditemukan".into(),
        })?);
        return Ok(res);
    }

    let row = row.unwrap();

    let user_id: i64 = row.try_get("id")?;
    let db_password: String = row.try_get("password")?;

    if !bcrypt::verify(&data.password, &db_password)? {
        let mut res = Response::new(StatusCode::Unauthorized);
        res.set_body(tide::Body::from_json(&LoginResponse {
            status: "Failed".into(),
            message: "Password salah".into(),
        })?);
        return Ok(res);
    }

    sqlx::query("UPDATE users SET logged_in = 1 WHERE id = ?")
        .bind(user_id)
        .execute(pool)
        .await?;

    let mut res = Response::new(StatusCode::Ok);
    res.set_body(tide::Body::from_json(&LoginResponse {
        status: "success".into(),
        message: "Berhasil Login".into(),
    })?);

    Ok(res)
}

async fn logout(mut req: Request<SqlitePool>) -> tide::Result {
    let data: LogoutRequest = req.body_json().await?;
    let pool = req.state();

    let result = sqlx::query("UPDATE users SET logged_in = 0 WHERE username = ?")
        .bind(&data.username)
        .execute(pool)
        .await?;

    if result.rows_affected() == 0 {
        let mut res = Response::new(StatusCode::BadRequest);
        res.set_body(tide::Body::from_json(&LogoutResponse {
            status: "error".into(),
            message: "User tidak ditemukan".into(),
        })?);
        return Ok(res);
    }

    let mut res = Response::new(StatusCode::Ok);
    res.set_body(tide::Body::from_json(&LogoutResponse {
        status: "success".into(),
        message: "Sayonara".into(),
    })?);

    Ok(res)
}

async fn register(mut req: Request<SqlitePool>) -> tide::Result {
    let data: RegisterRequest = req.body_json().await?;

    let pool = req.state();

    let hashed = bcrypt::hash(data.password, bcrypt::DEFAULT_COST)?;

    let result = sqlx::query(
        r#"
        INSERT INTO users (username, password, logged_in)
        VALUES (?, ?, 0)
        "#,
    )
    .bind(data.username)
    .bind(hashed)
    .execute(pool)
    .await;

    match result {
        Ok(_) => {
            let mut res = Response::new(StatusCode::Ok);
            res.set_body(tide::Body::from_json(&RegisterResponse {
                status: "success".into(),
                message: "Berhasil Daftar".into(),
            })?);
            Ok(res)
        }
        Err(e) => {
            let mut res = Response::new(StatusCode::BadRequest);
            res.set_body(tide::Body::from_json(&RegisterResponse {
                status: "Failed".into(),
                message: format!("Gagal Daftar: {}", e),
            })?);
            Ok(res)
        }
    }
}

async fn get_movies(req: Request<SqlitePool>) -> tide::Result {
    let pool = req.state();

    let movies: Vec<Movie> = sqlx::query_as::<_, Movie>(
        r#"
        SELECT
            id, adult, backdrop_path, genre_ids, origin_country,
            original_language, original_name, original_title,
            overview, popularity, poster_path, first_air_date,
            release_date, name, title, video, vote_average, vote_count
        FROM movies
        "#,
    )
    .fetch_all(pool)
    .await?;

    let base_url = "https://image.tmdb.org/t/p/original";
    let movies: Vec<Movie> = movies
        .into_iter()
        .map(|mut movie| {
            if let Some(ref path) = movie.backdrop_path {
                movie.backdrop_path = Some(format!("{}{}", base_url, path));
            }
            if let Some(ref path) = movie.poster_path {
                movie.poster_path = Some(format!("{}{}", base_url, path));
            }
            movie
        })
        .collect();

    let mut res = Response::new(StatusCode::Ok);
    res.set_body(tide::Body::from_json(&movies)?);
    Ok(res)
}

async fn post_chat(mut req: Request<SqlitePool>) -> tide::Result {
    let data: SendChatRequest = req.body_json().await?;
    let pool = req.state();

    if data.chat.trim().is_empty() {
        let mut res = Response::new(StatusCode::BadRequest);
        res.set_body(tide::Body::from_json(&ChatResponse {
            status: "error".into(),
            message: "Pesan chat tidak boleh kosong".into(),
        })?);
        return Ok(res);
    }

    let result = sqlx::query(
        r#"
        INSERT INTO chats (movie_id, user_id, chat)
        VALUES (?, ?, ?)
        "#,
    )
    .bind(data.movie_id)
    .bind(data.user_id)
    .bind(&data.chat)
    .execute(pool)
    .await;

    match result {
        Ok(_) => {
            let mut res = Response::new(StatusCode::Ok);
            res.set_body(tide::Body::from_json(&ChatResponse {
                status: "success".into(),
                message: "Pesan terkirim".into(),
            })?);
            Ok(res)
        }
        Err(e) => {
            let mut res = Response::new(StatusCode::InternalServerError);
            res.set_body(tide::Body::from_json(&ChatResponse {
                status: "error".into(),
                message: format!("Gagal mengirim pesan: {}", e),
            })?);
            Ok(res)
        }
    }
}

async fn get_chats(req: Request<SqlitePool>) -> tide::Result {
    let pool = req.state();

    let movie_id_param = req.param("movie_id")?;
    let movie_id: i32 = movie_id_param.parse().unwrap_or(0);

    let chats: Vec<ChatMessage> = sqlx::query_as::<_, ChatMessage>(
        r#"
        SELECT
            c.chat_id,
            c.movie_id,
            c.user_id,
            u.username,
            c.chat,
            c.created_at
        FROM chats c
        JOIN users u ON c.user_id = u.id
        WHERE c.movie_id = ?
        ORDER BY c.created_at ASC
        "#,
    )
    .bind(movie_id)
    .fetch_all(pool)
    .await?;

    let mut res = Response::new(StatusCode::Ok);
    res.set_body(tide::Body::from_json(&chats)?);
    Ok(res)
}
