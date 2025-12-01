// app.js — версия с better-sqlite3 и настоящей БД

const express = require('express');
const path = require('path');
const session = require('express-session');
const flash = require('connect-flash');
const methodOverride = require('method-override');
const bcrypt = require('bcryptjs');
const { db } = require('./db');
const engine = require('ejs-locals');

const app = express();

// ========= Настройки =========
const PORT = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET || 'super-secret-session-key';

// ========= Middleware =========
app.engine('ejs', engine);
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.use(methodOverride('_method'));

app.use(
    session({
        secret: SESSION_SECRET,
        resave: false,
        saveUninitialized: false
    })
);

app.use(flash());

// Пользователь и флеши в шаблонах
app.use((req, res, next) => {
    res.locals.currentUser = req.session.user;
    res.locals.success = req.flash('success');
    res.locals.error = req.flash('error');
    next();
});

// ========= Инициализация админа при первом запуске =========
(function initAdminUser() {
    const row = db.prepare('SELECT COUNT(*) AS cnt FROM users').get();
    const userCount = row ? row.cnt : 0;

    if (userCount === 0) {
        const username = 'admin';
        const password = 'change-me-strong-password'; // СМЕНИ после запуска
        const hash = bcrypt.hashSync(password, 10);
        db.prepare(
            'INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, 1)'
        ).run(username, hash);
        console.log('Создан админ-пользователь:');
        console.log(`  логин: ${username}`);
        console.log(`  пароль: ${password}`);
    }
})();

// ========= Счётчик посещений сайта =========
// ========= Счётчик посещений сайта (уникальные сессии в день) =========
function incrementVisitCounter(req, res, next) {
    try {
        // Не считаем переходы по /admin (чтобы твои собственные клики не портили статистику)
        if (req.path.startsWith('/admin')) {
            return next();
        }

        const today = new Date();
        const dateStr = today.toISOString().slice(0, 10); // YYYY-MM-DD

        // Если в сессии уже записано, что сегодня этот пользователь был, второй раз не считаем
        if (req.session && req.session.lastVisitDate === dateStr) {
            return next();
        }

        // Обновляем дату последнего визита в сессии
        if (req.session) {
            req.session.lastVisitDate = dateStr;
        }

        // Инкрементируем счётчик посещений за день
        const existing = db
            .prepare('SELECT count FROM visits WHERE date = ?')
            .get(dateStr);

        if (existing) {
            db.prepare('UPDATE visits SET count = count + 1 WHERE date = ?').run(
                dateStr
            );
        } else {
            db.prepare('INSERT INTO visits (date, count) VALUES (?, 1)').run(dateStr);
        }
    } catch (e) {
        console.error('Ошибка счётчика посещений:', e.message);
    }

    next();
}

app.use(incrementVisitCounter);


// ========= Middleware для защиты админки =========
function requireAdmin(req, res, next) {
    if (!req.session.user || !req.session.user.is_admin) {
        req.flash('error', 'Требуется авторизация администратора');
        return res.redirect('/admin/login');
    }
    next();
}

// ========= Middleware: нужен любой залогиненный пользователь =========
function requireLogin(req, res, next) {
    if (!req.session.user) {
        req.flash('error', 'Нужно войти в аккаунт');
        return res.redirect('/login');
    }
    next();
}

// ========= Публичные страницы =========

// Главная
app.get('/', (req, res) => {
    const totalPosts = db.prepare('SELECT COUNT(*) AS c FROM posts').get().c;
    const totalInterviews = db
        .prepare('SELECT COUNT(*) AS c FROM interviews')
        .get().c;
    const totalPublications = db
        .prepare('SELECT COUNT(*) AS c FROM publications')
        .get().c;

    const latestPosts = db
        .prepare(
            'SELECT id, slug, title, summary, created_at, views FROM posts ORDER BY created_at DESC LIMIT 3'
        )
        .all();

    res.render('pages/index', {
        title: 'Daria Pharma Vox',
        totalPosts,
        totalInterviews,
        totalPublications,
        latestPosts
    });
});

// Интервью
app.get('/interviews', (req, res) => {
    const interviews = db
        .prepare(
            'SELECT id, title, video_url, project_description, goals, relevance, highlights, created_at FROM interviews ORDER BY created_at DESC'
        )
        .all()
        .map((i) => ({
            ...i,
            highlights: i.highlights ? JSON.parse(i.highlights) : []
        }));

    res.render('pages/interviews', {
        title: 'Интервью и проект адаптации',
        interviews
    });
});

// Публикации
app.get('/publications', (req, res) => {
    const publications = db
        .prepare(
            'SELECT id, title, journal, year, status, link, notes, created_at FROM publications ORDER BY year DESC, created_at DESC'
        )
        .all();

    res.render('pages/publications', {
        title: 'Научные публикации',
        publications
    });
});

// Блог "Фарма-жизнь"
app.get('/pharma-life', (req, res) => {
    const posts = db
        .prepare(
            `SELECT 
                p.id,
                p.slug,
                p.title,
                p.summary,
                p.created_at,
                p.views,
                (SELECT COUNT(*) FROM likes l WHERE l.post_id = p.id) AS likes
             FROM posts p
             ORDER BY p.created_at DESC`
        )
        .all();

    res.render('pages/pharma-life', {
        title: 'Фарма-жизнь',
        posts
    });
});


// Статья блога
app.get('/pharma-life/:slug', (req, res) => {
    const { slug } = req.params;
    const post = db
        .prepare('SELECT * FROM posts WHERE slug = ?')
        .get(slug);

    if (!post) {
        return res.status(404).send('Статья не найдена');
    }

    // увеличиваем просмотры
    db.prepare('UPDATE posts SET views = views + 1 WHERE id = ?').run(post.id);
    post.views += 1;

    // количество лайков
    const likesRow = db
        .prepare('SELECT COUNT(*) AS cnt FROM likes WHERE post_id = ?')
        .get(post.id);
    post.likes = likesRow ? likesRow.cnt : 0;

    // лайкнул ли этот пользователь
    let userLiked = false;
    if (req.session.user) {
        const likedRow = db
            .prepare('SELECT 1 FROM likes WHERE user_id = ? AND post_id = ?')
            .get(req.session.user.id, post.id);
        userLiked = !!likedRow;
    }

    res.render('pages/post', {
        title: post.title,
        post,
        userLiked
    });
});

// Поставить / убрать лайк к посту
app.post('/pharma-life/:slug/like', requireLogin, (req, res) => {
    const { slug } = req.params;
    const userId = req.session.user.id;

    const post = db
        .prepare('SELECT id FROM posts WHERE slug = ?')
        .get(slug);

    if (!post) {
        req.flash('error', 'Статья не найдена');
        return res.redirect('/pharma-life');
    }

    const existing = db
        .prepare('SELECT id FROM likes WHERE user_id = ? AND post_id = ?')
        .get(userId, post.id);

    try {
        if (existing) {
            // уже лайкнул — убираем лайк
            db.prepare('DELETE FROM likes WHERE id = ?').run(existing.id);
        } else {
            // ещё не лайкнул — добавляем
            db.prepare('INSERT INTO likes (user_id, post_id) VALUES (?, ?)').run(
                userId,
                post.id
            );
        }
    } catch (e) {
        console.error('Ошибка лайка:', e);
        req.flash('error', 'Не удалось обновить лайк');
    }

    res.redirect('/pharma-life/' + slug);
});

// ========= Регистрация и вход обычных пользователей =========

// Страница регистрации
app.get('/register', (req, res) => {
    if (req.session.user) return res.redirect('/');
    res.render('auth/register', { title: 'Регистрация' });
});

// Обработка регистрации
app.post('/register', (req, res) => {
    const { username, password, confirm } = req.body;

    if (!username || !password) {
        req.flash('error', 'Заполните логин и пароль');
        return res.redirect('/register');
    }

    if (password !== confirm) {
        req.flash('error', 'Пароли не совпадают');
        return res.redirect('/register');
    }

    try {
        const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
        if (existing) {
            req.flash('error', 'Пользователь с таким логином уже существует');
            return res.redirect('/register');
        }

        const hash = bcrypt.hashSync(password, 10);
        const info = db.prepare(
            'INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, 0)'
        ).run(username, hash);

        // Сразу логиним пользователя
        req.session.user = {
            id: info.lastInsertRowid,
            username,
            is_admin: 0
        };

        req.flash('success', 'Регистрация прошла успешно');
        res.redirect('/');
    } catch (e) {
        console.error('Ошибка регистрации:', e);
        req.flash('error', 'Не удалось зарегистрироваться');
        res.redirect('/register');
    }
});

// Страница входа пользователя
app.get('/login', (req, res) => {
    if (req.session.user) return res.redirect('/');
    res.render('auth/login', { title: 'Вход в аккаунт' });
});

// Обработка входа пользователя
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const user = db
        .prepare('SELECT * FROM users WHERE username = ?')
        .get(username);

    if (!user) {
        req.flash('error', 'Неверный логин или пароль');
        return res.redirect('/login');
    }

    const isValid = bcrypt.compareSync(password, user.password_hash);
    if (!isValid) {
        req.flash('error', 'Неверный логин или пароль');
        return res.redirect('/login');
    }

    req.session.user = {
        id: user.id,
        username: user.username,
        is_admin: !!user.is_admin
    };

    req.flash('success', 'Вы вошли в аккаунт');

    if (user.is_admin) {
        return res.redirect('/admin');
    }
    res.redirect('/');
});

// ========= Админка: авторизация =========

// Форма логина
app.get('/admin/login', (req, res) => {
    res.render('admin/login', { title: 'Вход администратора' });
});

// Логин
app.post('/admin/login', (req, res) => {
    const { username, password } = req.body;
    const user = db
        .prepare('SELECT * FROM users WHERE username = ?')
        .get(username);

    if (!user) {
        req.flash('error', 'Неверный логин или пароль');
        return res.redirect('/admin/login');
    }

    const isValid = bcrypt.compareSync(password, user.password_hash);
    if (!isValid) {
        req.flash('error', 'Неверный логин или пароль');
        return res.redirect('/admin/login');
    }

    req.session.user = {
        id: user.id,
        username: user.username,
        is_admin: !!user.is_admin
    };
    req.flash('success', 'Вы вошли как администратор');
    res.redirect('/admin');
});

// Logout
app.post('/admin/logout', (req, res) => {
    req.session.destroy(() => {
        res.redirect('/');
    });
});

// ========= Админка: смена пароля =========

// Форма смены пароля
app.get('/admin/password', requireAdmin, (req, res) => {
    res.render('admin/password', { title: 'Смена пароля' });
});

// Обработка формы смены пароля
app.post('/admin/password', requireAdmin, (req, res) => {
    const { currentPassword, newPassword, newPassword2 } = req.body;

    // Берём текущего пользователя из БД
    const user = db
        .prepare('SELECT * FROM users WHERE id = ?')
        .get(req.session.user.id);

    if (!user) {
        req.flash('error', 'Пользователь не найден');
        return res.redirect('/admin');
    }

    // Проверяем текущий пароль
    const isValid = bcrypt.compareSync(currentPassword, user.password_hash);
    if (!isValid) {
        req.flash('error', 'Текущий пароль введён неверно');
        return res.redirect('/admin/password');
    }

    // Проверяем совпадение нового пароля
    if (newPassword !== newPassword2) {
        req.flash('error', 'Новый пароль и подтверждение не совпадают');
        return res.redirect('/admin/password');
    }

    // Можно добавить простую проверку длины
    if (!newPassword || newPassword.length < 8) {
        req.flash('error', 'Новый пароль должен быть не короче 8 символов');
        return res.redirect('/admin/password');
    }

    // Хешируем новый пароль и сохраняем в БД
    const newHash = bcrypt.hashSync(newPassword, 10);
    db.prepare('UPDATE users SET password_hash = ? WHERE id = ?')
        .run(newHash, user.id);

    req.flash('success', 'Пароль успешно изменён');
    res.redirect('/admin');
});


// ========= Админка: панель и статистика =========
app.get('/admin', requireAdmin, (req, res) => {
    // Последние 7 дней
    const visitsLast7 = db
        .prepare(
            `SELECT date, count FROM visits ORDER BY date DESC LIMIT 7`
        )
        .all();

    const totalVisitsAllTimeRow = db
        .prepare('SELECT SUM(count) AS total FROM visits')
        .get();
    const totalVisitsAllTime = totalVisitsAllTimeRow && totalVisitsAllTimeRow.total ?
        totalVisitsAllTimeRow.total :
        0;

    // 🔹 Количество обычных пользователей (is_admin = 0)
    const totalUsersRow = db
        .prepare('SELECT COUNT(*) AS c FROM users WHERE is_admin = 0')
        .get();
    const totalUsers = totalUsersRow ? totalUsersRow.c : 0;

    // (по желанию) сколько админов
    const totalAdminsRow = db
        .prepare('SELECT COUNT(*) AS c FROM users WHERE is_admin = 1')
        .get();
    const totalAdmins = totalAdminsRow ? totalAdminsRow.c : 0;

    const latestPosts = db
        .prepare(
            'SELECT id, title, created_at, views FROM posts ORDER BY created_at DESC LIMIT 5'
        )
        .all();

    res.render('admin/dashboard', {
        title: 'Админ-панель',
        visitsLast7,
        totalVisitsAllTime,
        latestPosts,
        totalUsers,
        totalAdmins
    });
});


// Сброс счётчика посещений
app.post('/admin/reset-visits', requireAdmin, (req, res) => {
    db.exec('DELETE FROM visits'); // удаляем все записи из таблицы visits
    req.flash('success', 'Счётчик посещений сброшен');
    res.redirect('/admin');
});


// ========= Админка: Интервью =========
app.get('/admin/interviews/new', requireAdmin, (req, res) => {
    res.render('admin/interviews_new', { title: 'Новое интервью' });
});

app.post('/admin/interviews', requireAdmin, (req, res) => {
    const {
        title,
        video_url,
        project_description,
        goals,
        relevance,
        highlights
    } = req.body;

    const highlightsArray = highlights ?
        highlights
        .split('\n')
        .map((s) => s.trim())
        .filter(Boolean) : [];

    db.prepare(
        `INSERT INTO interviews 
     (title, video_url, project_description, goals, relevance, highlights)
     VALUES (?, ?, ?, ?, ?, ?)`
    ).run(
        title,
        video_url,
        project_description,
        goals,
        relevance,
        JSON.stringify(highlightsArray)
    );

    req.flash('success', 'Интервью добавлено');
    res.redirect('/interviews');
});

// Список интервью для админа
app.get('/admin/interviews', requireAdmin, (req, res) => {
    const interviews = db
        .prepare(
            'SELECT id, title, created_at FROM interviews ORDER BY created_at DESC'
        )
        .all();

    res.render('admin/interviews_index', {
        title: 'Управление интервью',
        interviews
    });
});

// Форма редактирования интервью
app.get('/admin/interviews/:id/edit', requireAdmin, (req, res) => {
    const { id } = req.params;
    const interview = db
        .prepare('SELECT * FROM interviews WHERE id = ?')
        .get(id);

    if (!interview) {
        req.flash('error', 'Интервью не найдено');
        return res.redirect('/admin/interviews');
    }

    const highlightsText = interview.highlights ?
        JSON.parse(interview.highlights).join('\n') :
        '';

    res.render('admin/interviews_edit', {
        title: 'Редактирование интервью',
        interview,
        highlightsText
    });
});

// Обновление интервью
app.put('/admin/interviews/:id', requireAdmin, (req, res) => {
    const { id } = req.params;
    const {
        title,
        video_url,
        project_description,
        goals,
        relevance,
        highlights
    } = req.body;

    const highlightsArray = highlights ?
        highlights
        .split('\n')
        .map((s) => s.trim())
        .filter(Boolean) : [];

    db.prepare(
        `UPDATE interviews
         SET title = ?, video_url = ?, project_description = ?, goals = ?, relevance = ?, highlights = ?
         WHERE id = ?`
    ).run(
        title,
        video_url,
        project_description,
        goals,
        relevance,
        JSON.stringify(highlightsArray),
        id
    );

    req.flash('success', 'Интервью обновлено');
    res.redirect('/admin/interviews');
});

// Удаление интервью
app.delete('/admin/interviews/:id', requireAdmin, (req, res) => {
    const { id } = req.params;
    db.prepare('DELETE FROM interviews WHERE id = ?').run(id);
    req.flash('success', 'Интервью удалено');
    res.redirect('/admin/interviews');
});

// ========= Админка: Публикации =========
app.get('/admin/publications/new', requireAdmin, (req, res) => {
    res.render('admin/publications_new', { title: 'Новая публикация' });
});

app.post('/admin/publications', requireAdmin, (req, res) => {
    const { title, journal, year, status, link, notes } = req.body;

    db.prepare(
        `INSERT INTO publications 
     (title, journal, year, status, link, notes)
     VALUES (?, ?, ?, ?, ?, ?)`
    ).run(title, journal, year || null, status, link, notes);

    req.flash('success', 'Публикация добавлена');
    res.redirect('/publications');
});

// Список публикаций для админа
app.get('/admin/publications', requireAdmin, (req, res) => {
    const publications = db
        .prepare(
            'SELECT id, title, journal, year, status, created_at FROM publications ORDER BY year DESC, created_at DESC'
        )
        .all();

    res.render('admin/publications_index', {
        title: 'Управление публикациями',
        publications
    });
});

// Форма редактирования публикации
app.get('/admin/publications/:id/edit', requireAdmin, (req, res) => {
    const { id } = req.params;
    const publication = db
        .prepare('SELECT * FROM publications WHERE id = ?')
        .get(id);

    if (!publication) {
        req.flash('error', 'Публикация не найдена');
        return res.redirect('/admin/publications');
    }

    res.render('admin/publications_edit', {
        title: 'Редактирование публикации',
        publication
    });
});

// Обновление публикации
app.put('/admin/publications/:id', requireAdmin, (req, res) => {
    const { id } = req.params;
    const { title, journal, year, status, link, notes } = req.body;

    db.prepare(
        `UPDATE publications
         SET title = ?, journal = ?, year = ?, status = ?, link = ?, notes = ?
         WHERE id = ?`
    ).run(title, journal, year || null, status, link, notes, id);

    req.flash('success', 'Публикация обновлена');
    res.redirect('/admin/publications');
});

// Удаление публикации
app.delete('/admin/publications/:id', requireAdmin, (req, res) => {
    const { id } = req.params;
    db.prepare('DELETE FROM publications WHERE id = ?').run(id);
    req.flash('success', 'Публикация удалена');
    res.redirect('/admin/publications');
});

// ========= Админка: Посты "Фарма-жизнь" =========
app.get('/admin/posts/new', requireAdmin, (req, res) => {
    res.render('admin/posts_new', { title: 'Новая запись блога' });
});

function slugify(str) {
    return str
        .toString()
        .normalize('NFD')
        .replace(/[\u0300-\u036f]/g, '')
        .replace(/[^a-zA-Z0-9]+/g, '-')
        .replace(/^-+|-+$/g, '')
        .toLowerCase();
}

app.post('/admin/posts', requireAdmin, (req, res) => {
    const { title, summary, content } = req.body;
    let slug = slugify(title);
    if (!slug) slug = 'post-' + Date.now();

    let exists = db.prepare('SELECT id FROM posts WHERE slug = ?').get(slug);
    let suffix = 1;
    let baseSlug = slug;
    while (exists) {
        slug = `${baseSlug}-${suffix++}`;
        exists = db.prepare('SELECT id FROM posts WHERE slug = ?').get(slug);
    }

    db.prepare(
        `INSERT INTO posts (slug, title, summary, content)
     VALUES (?, ?, ?, ?)`
    ).run(slug, title, summary, content);

    req.flash('success', 'Запись блога создана');
    res.redirect(`/pharma-life/${slug}`);
});

// Список постов "Фарма-жизнь" для админа
app.get('/admin/posts', requireAdmin, (req, res) => {
    const posts = db
        .prepare(
            'SELECT id, slug, title, created_at, views FROM posts ORDER BY created_at DESC'
        )
        .all();

    res.render('admin/posts_index', {
        title: 'Управление постами «Фарма-жизнь»',
        posts
    });
});

// Форма редактирования поста
app.get('/admin/posts/:id/edit', requireAdmin, (req, res) => {
    const { id } = req.params;
    const post = db
        .prepare('SELECT * FROM posts WHERE id = ?')
        .get(id);

    if (!post) {
        req.flash('error', 'Пост не найден');
        return res.redirect('/admin/posts');
    }

    res.render('admin/posts_edit', {
        title: 'Редактирование поста «Фарма-жизнь»',
        post
    });
});

// Обновление поста (slug не трогаем, чтобы ссылки не ломались)
app.put('/admin/posts/:id', requireAdmin, (req, res) => {
    const { id } = req.params;
    const { title, summary, content } = req.body;

    db.prepare(
        `UPDATE posts
         SET title = ?, summary = ?, content = ?, updated_at = CURRENT_TIMESTAMP
         WHERE id = ?`
    ).run(title, summary, content, id);

    req.flash('success', 'Пост обновлён');
    res.redirect('/admin/posts');
});

// Удаление поста
app.delete('/admin/posts/:id', requireAdmin, (req, res) => {
    const { id } = req.params;
    db.prepare('DELETE FROM posts WHERE id = ?').run(id);
    req.flash('success', 'Пост удалён');
    res.redirect('/admin/posts');
});

// ========= Запуск сервера =========
app.listen(PORT, () => {
    console.log(`Сайт запущен на http://localhost:${PORT}`);
});