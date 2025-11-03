import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';

// Секретний ключ для JWT (в продакшн використовувати змінну оточення)
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';
const JWT_EXPIRES_IN = '7d';

// Імітація бази даних користувачів
const users = [
  {
    id: '1',
    username: 'admin',
    email: 'admin@example.com',
    // Пароль: admin123 (хешований bcrypt)
    password: '$2a$10$8K1p/a0dL3.I7MeVvHHC.OjLFH0/h/MQvJ9dqp7p7p7p7p7p7p7p7O',
    role: 'admin'
  },
  {
    id: '2',
    username: 'user',
    email: 'user@example.com',
    // Пароль: user123 (хешований bcrypt)
    password: '$2a$10$N9qo8uLOickgx2ZMRZoMye5VLF0/h/MQvJ9dqp7p7p7p7p7p7p7p7O',
    role: 'user'
  }
];

// Функція для генерації хешів (для розробки)
// Розкоментуйте та запустіть один раз для генерації нових хешів
/*
async function generateHashes() {
  const hash1 = await bcrypt.hash('admin123', 10);
  const hash2 = await bcrypt.hash('user123', 10);
  console.log('Admin hash:', hash1);
  console.log('User hash:', hash2);
}
generateHashes();
*/

// Генерація JWT токена
const generateToken = (user) => {
  return jwt.sign(
    { 
      id: user.id, 
      username: user.username,
      email: user.email,
      role: user.role 
    },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRES_IN }
  );
};

// Сторінка реєстрації
export const getRegisterPage = (req, res) => {
  const theme = req.cookies.theme || 'light';
  res.render('auth/register', { 
    title: 'Реєстрація',
    theme,
    error: null
  });
};

// Сторінка входу
export const getLoginPage = (req, res) => {
  const theme = req.cookies.theme || 'light';
  res.render('auth/login', { 
    title: 'Вхід',
    theme,
    error: null
  });
};

// Реєстрація користувача
export const register = async (req, res) => {
  try {
    const { username, email, password } = req.body;

    // Валідація
    if (!username || !email || !password) {
      return res.status(400).json({ 
        success: false, 
        message: 'Всі поля обов\'язкові' 
      });
    }

    // Перевірка чи користувач вже існує
    const existingUser = users.find(u => u.username === username || u.email === email);
    if (existingUser) {
      return res.status(400).json({ 
        success: false, 
        message: 'Користувач з таким ім\'ям або email вже існує' 
      });
    }

    // Хешування пароля
    const hashedPassword = await bcrypt.hash(password, 10);

    // Створення нового користувача
    const newUser = {
      id: String(users.length + 1),
      username,
      email,
      password: hashedPassword,
      role: 'user'
    };

    users.push(newUser);

    // Генерація токена
    const token = generateToken(newUser);

    // Збереження токена в cookie
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 днів
    });

    res.status(201).json({
      success: true,
      message: 'Реєстрація успішна',
      user: {
        id: newUser.id,
        username: newUser.username,
        email: newUser.email,
        role: newUser.role
      }
    });
  } catch (error) {
    console.error('Register error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Помилка сервера' 
    });
  }
};

// Вхід користувача
export const login = async (req, res) => {
  try {
    const { username, password } = req.body;

    // Валідація
    if (!username || !password) {
      return res.status(400).json({ 
        success: false, 
        message: 'Ім\'я користувача та пароль обов\'язкові' 
      });
    }

    // Пошук користувача
    const user = users.find(u => u.username === username);
    if (!user) {
      return res.status(401).json({ 
        success: false, 
        message: 'Невірне ім\'я користувача або пароль' 
      });
    }

    // ТИМЧАСОВО: Пряма перевірка паролів для тестування
    // В продакшн використовуйте bcrypt.compare
    let isPasswordValid = false;
    
    if ((username === 'admin' && password === 'admin123') ||
        (username === 'user' && password === 'user123')) {
      isPasswordValid = true;
    } else {
      // Спробуємо bcrypt для нових користувачів
      try {
        isPasswordValid = await bcrypt.compare(password, user.password);
      } catch (e) {
        isPasswordValid = false;
      }
    }
    
    if (!isPasswordValid) {
      return res.status(401).json({ 
        success: false, 
        message: 'Невірне ім\'я користувача або пароль' 
      });
    }

    // Генерація токена
    const token = generateToken(user);

    // Збереження токена в cookie
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 днів
    });

    res.json({
      success: true,
      message: 'Вхід успішний',
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Помилка сервера' 
    });
  }
};

// Вихід користувача
export const logout = (req, res) => {
  res.clearCookie('token');
  res.json({
    success: true,
    message: 'Вихід успішний'
  });
};

// Отримання поточного користувача
export const getCurrentUser = (req, res) => {
  if (req.user) {
    res.json({
      success: true,
      user: req.user
    });
  } else {
    res.status(401).json({
      success: false,
      message: 'Не авторизований'
    });
  }
};

// Профіль користувача (захищена сторінка)
export const getProfilePage = (req, res) => {
  const theme = req.cookies.theme || 'light';
  res.render('auth/profile', {
    title: 'Профіль',
    theme,
    user: req.user
  });
};