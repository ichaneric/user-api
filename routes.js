const express = require('express');
const router = express.Router();
const { authenticateJWT } = require('./middleware'); // Import middleware
const { validateUser, createUser, updateUser, getUserById, deleteUser } = require('./user');

// --- Register API ---
router.post('/register', async (req, res) => {
  const { username, password } = req.body;

  const { error } = validateUser({ username, password });
  if (error) {
    return res.status(400).json({ error: error.details[0].message });
  }

  try {
    const newUser = await createUser(username, password);
    res.status(201).json({
      message: 'User registered successfully',
      user: { id: newUser.id, username: newUser.username }
    });
  } catch (error) {
    console.error('Error registering user:', error);
    if (error.code === 'SQLITE_CONSTRAINT') {
      return res.status(409).json({ error: 'Username already exists' });
    }
    res.status(500).json({ error: 'Failed to register user' });
  }
});

// --- Login API ---
router.post('/login', async (req, res) => {
  const { username, password } = req.body;

  // --- Validation using Joi ---
  const schema = Joi.object({
    username: Joi.string().alphanum().min(3).max(30).required(),
    password: Joi.string().min(6).required(),
  });

  const { error } = schema.validate({ username, password });
  if (error) {
    return res.status(400).json({ error: error.details[0].message });
  }

  try {
    const user = await getUserById(username); // Assuming getUserById fetches by username
    if (!user) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    const token = jwt.sign({ userId: user.id }, 'your_jwt_secret');
    res.json({ message: 'Login successful', token });
  } catch (error) {
    console.error('Error during login:', error);
    res.status(500).json({ error: 'Failed to log in' });
  }
});

// --- Add User API ---
router.post('/users', /* authenticateJWT, */ async (req, res) => {
  const { username, password } = req.body;

  const { error } = validateUser({ username, password });
  if (error) {
    return res.status(400).json({ error: error.details[0].message });
  }

  try {
    const newUser = await createUser(username, password);
    res.status(201).json({
      message: 'User added successfully',
      user: { id: newUser.id, username: newUser.username }
    });
  } catch (error) {
    console.error('Error adding user:', error);
    if (error.code === 'SQLITE_CONSTRAINT') {
      return res.status(409).json({ error: 'Username already exists' });
    }
    res.status(500).json({ error: 'Failed to add user' });
  }
});

// --- Update User API ---
router.put('/users/:id', /* authenticateJWT, */ async (req, res) => {
  const userId = parseInt(req.params.id);
  const { username, password } = req.body;

  const { error } = validateUser({ username, password });
  if (error) {
    return res.status(400).json({ error: error.details[0].message });
  }

  try {
    await updateUser(userId, username, password);
    res.json({
      message: 'User updated successfully',
      user: { id: userId, username: username }
    });
  } catch (error) {
    console.error('Error updating user:', error);
    res.status(500).json({ error: 'Failed to update user' });
  }
});

// --- Get User API ---
router.get('/users/:id', /* authenticateJWT, */ async (req, res) => {
  const userId = parseInt(req.params.id);

  try {
    const user = await getUserById(userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json(user);
  } catch (error) {
    console.error('Error getting user:', error);
    res.status(500).json({ error: 'Failed to get user' });
  }
});

// --- Delete User API ---
router.delete('/users/:id', /* authenticateJWT, */ async (req, res) => {
  const userId = parseInt(req.params.id);

  try {
    await deleteUser(userId);
    res.sendStatus(204);
  } catch (error) {
    console.error('Error deleting user:', error);
    res.status(500).json({ error: 'Failed to delete user' });
  }
});

module.exports = router;
