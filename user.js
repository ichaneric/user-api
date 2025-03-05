const bcrypt = require('bcrypt');
const Joi = require('joi');
const db = require('./db'); // Import the database connection

const userSchema = Joi.object({
  username: Joi.string().alphanum().min(3).max(30).required(),
  password: Joi.string().min(6).required(),
});

const validateUser = (user) => {
  return userSchema.validate(user);
};

const createUser = async (username, password) => {
  const hashedPassword = await bcrypt.hash(password, 10);
  return new Promise((resolve, reject) => {
    db.run(
      'INSERT INTO users (username, password) VALUES (?, ?)',
      [username, hashedPassword],
      function (err) {
        if (err) {
          reject(err);
        } else {
          resolve({ id: this.lastID, username });
        }
      }
    );
  });
};

const updateUser = async (userId, username, password) => {
  return new Promise(async (resolve, reject) => {
    try {
      if (password) {
        const hashedPassword = await bcrypt.hash(password, 10);
        db.run('UPDATE users SET username = ?, password = ? WHERE id = ?', [username, hashedPassword, userId], (err) => {
          if (err) reject(err);
          resolve();
        });
      } else {
        db.run('UPDATE users SET username = ? WHERE id = ?', [username, userId], (err) => {
          if (err) reject(err);
          resolve();
        });
      }
    } catch (error) {
      reject(error);
    }
  });
};

const getUserById = (userId) => {
  return new Promise((resolve, reject) => {
    db.get('SELECT id, username FROM users WHERE id = ?', [userId], (err, row) => {
      if (err) reject(err);
      resolve(row);
    });
  });
};

const deleteUser = (userId) => {
  return new Promise((resolve, reject) => {
    db.run('DELETE FROM users WHERE id = ?', [userId], (err) => {
      if (err) reject(err);
      resolve();
    });
  });
};

module.exports = { validateUser, createUser, updateUser, getUserById, deleteUser };