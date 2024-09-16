// app.js
const express = require('express');
const swaggerJsdoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
app.use(express.json());

// PostgreSQL connection
const pool = new Pool({
  connectionString: process.env.POSTGRES_URL,
});

// Swagger definition
const swaggerOptions = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'E-commerce API',
      version: '1.0.0',
      description: 'API for an e-commerce platform',
    },
    servers: [
      {
        url: process.env.PUBLIC_SERVER_URL || 'http://localhost:3000',
      },
    ],
  },
  apis: ['./app.js'], // Path to the API docs
};

const swaggerSpec = swaggerJsdoc(swaggerOptions);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

// Middleware to verify JWT
const verifyToken = (req, res, next) => {
  const token = req.headers['authorization'];
  if (!token) return res.status(403).send({ message: 'No token provided.' });

  jwt.verify(token, process.env.AUTH_SECRET, (err, decoded) => {
    if (err) return res.status(500).send({ message: 'Failed to authenticate token.' });
    req.userId = decoded.id;
    next();
  });
};

// Authentication APIs

/**
 * @swagger
 * /auth/register:
 *   post:
 *     summary: Register a new user
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *               - password
 *               - firstName
 *               - lastName
 *             properties:
 *               email:
 *                 type: string
 *               password:
 *                 type: string
 *               firstName:
 *                 type: string
 *               lastName:
 *                 type: string
 *     responses:
 *       201:
 *         description: User registered successfully
 *       400:
 *         description: Invalid input
 */
app.post('/auth/register', async (req, res) => {
  const { email, password, firstName, lastName } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO customer (email_address, first_name, last_name) VALUES ($1, $2, $3) RETURNING id',
      [email, firstName, lastName]
    );
    await pool.query(
      'INSERT INTO customer_login (customer_id, password_hash) VALUES ($1, $2)',
      [result.rows[0].id, password] // In real-world, hash the password
    );
    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    res.status(400).json({ message: 'Registration failed', error: error.message });
  }
});

/**
 * @swagger
 * /auth/login:
 *   post:
 *     summary: Login user
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *               - password
 *             properties:
 *               email:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       200:
 *         description: Login successful
 *       401:
 *         description: Invalid credentials
 */
app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query(
      'SELECT c.id, cl.password_hash FROM customer c JOIN customer_login cl ON c.id = cl.customer_id WHERE c.email_address = $1',
      [email]
    );
    if (result.rows.length > 0 && result.rows[0].password_hash === password) { // In real-world, compare hashed passwords
      const token = jwt.sign({ id: result.rows[0].id }, process.env.AUTH_SECRET, { expiresIn: '1h' });
      res.json({ auth: true, token });
    } else {
      res.status(401).json({ message: 'Invalid credentials' });
    }
  } catch (error) {
    res.status(500).json({ message: 'Login failed', error: error.message });
  }
});

// Product APIs

/**
 * @swagger
 * /products:
 *   get:
 *     summary: Get all products
 *     tags: [Products]
 *     parameters:
 *       - in: query
 *         name: page
 *         schema:
 *           type: integer
 *         description: Page number
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *         description: Number of items per page
 *     responses:
 *       200:
 *         description: List of products
 */
app.get('/products', async (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 10;
  const offset = (page - 1) * limit;

  try {
    const result = await pool.query('SELECT * FROM product LIMIT $1 OFFSET $2', [limit, offset]);
    const countResult = await pool.query('SELECT COUNT(*) FROM product');
    const totalProducts = parseInt(countResult.rows[0].count);
    const totalPages = Math.ceil(totalProducts / limit);

    res.json({
      products: result.rows,
      currentPage: page,
      totalPages: totalPages,
      totalProducts: totalProducts
    });
  } catch (error) {
    res.status(500).json({ message: 'Error fetching products', error: error.message });
  }
});

/**
 * @swagger
 * /products/{id}:
 *   get:
 *     summary: Get a product by ID
 *     tags: [Products]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Product details
 *       404:
 *         description: Product not found
 */
app.get('/products/:id', async (req, res) => {
  const productId = req.params.id;
  try {
    const result = await pool.query('SELECT * FROM product WHERE id = $1', [productId]);
    if (result.rows.length > 0) {
      res.json(result.rows[0]);
    } else {
      res.status(404).json({ message: 'Product not found' });
    }
  } catch (error) {
    res.status(500).json({ message: 'Error fetching product', error: error.message });
  }
});

// Shopping Cart APIs

/**
 * @swagger
 * /cart:
 *   get:
 *     summary: Get user's shopping cart
 *     tags: [Shopping Cart]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: User's shopping cart
 */
app.get('/cart', verifyToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT sci.*, p.name, p.price FROM shopping_cart_item sci JOIN product p ON sci.product_id = p.id WHERE sci.shopping_cart_id = (SELECT id FROM shopping_cart WHERE customer_id = $1)',
      [req.userId]
    );
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching shopping cart', error: error.message });
  }
});

/**
 * @swagger
 * /cart/items:
 *   post:
 *     summary: Add item to cart
 *     tags: [Shopping Cart]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - productId
 *               - quantity
 *             properties:
 *               productId:
 *                 type: integer
 *               quantity:
 *                 type: integer
 *     responses:
 *       201:
 *         description: Item added to cart
 *       400:
 *         description: Invalid input
 */
app.post('/cart/items', verifyToken, async (req, res) => {
  const { productId, quantity } = req.body;
  try {
    // First, ensure the shopping cart exists for the user
    let cartResult = await pool.query('SELECT id FROM shopping_cart WHERE customer_id = $1', [req.userId]);
    let cartId;
    if (cartResult.rows.length === 0) {
      // Create a new cart if it doesn't exist
      const newCartResult = await pool.query('INSERT INTO shopping_cart (customer_id) VALUES ($1) RETURNING id', [req.userId]);
      cartId = newCartResult.rows[0].id;
    } else {
      cartId = cartResult.rows[0].id;
    }

    // Now add the item to the cart
    await pool.query(
      'INSERT INTO shopping_cart_item (shopping_cart_id, product_id, quantity) VALUES ($1, $2, $3)',
      [cartId, productId, quantity]
    );
    res.status(201).json({ message: 'Item added to cart' });
  } catch (error) {
    res.status(400).json({ message: 'Error adding item to cart', error: error.message });
  }
});

// Order APIs

/**
 * @swagger
 * /orders:
 *   post:
 *     summary: Place a new order
 *     tags: [Orders]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - addressId
 *             properties:
 *               addressId:
 *                 type: integer
 *     responses:
 *       201:
 *         description: Order placed successfully
 *       400:
 *         description: Error placing order
 */
app.post('/orders', verifyToken, async (req, res) => {
  const { addressId } = req.body;
  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    // Create new order
    const orderResult = await client.query(
      'INSERT INTO "order" (customer_id, status_code_id) VALUES ($1, 1) RETURNING id', // Assuming 1 is the status code for 'new order'
      [req.userId]
    );
    const orderId = orderResult.rows[0].id;

    // Get items from the user's cart
    const cartItems = await client.query(
      'SELECT sci.product_id, sci.quantity, p.price FROM shopping_cart_item sci JOIN product p ON sci.product_id = p.id WHERE sci.shopping_cart_id = (SELECT id FROM shopping_cart WHERE customer_id = $1)',
      [req.userId]
    );

    // Add items to order
    for (let item of cartItems.rows) {
      await client.query(
        'INSERT INTO order_item (order_id, product_id, quantity, price) VALUES ($1, $2, $3, $4)',
        [orderId, item.product_id, item.quantity, item.price]
      );
    }

    // Clear the user's cart
    await client.query(
      'DELETE FROM shopping_cart_item WHERE shopping_cart_id = (SELECT id FROM shopping_cart WHERE customer_id = $1)',
      [req.userId]
    );

    await client.query('COMMIT');
    res.status(201).json({ message: 'Order placed successfully', orderId });
  } catch (error) {
    await client.query('ROLLBACK');
    res.status(400).json({ message: 'Error placing order', error: error.message });
  } finally {
    client.release();
  }
});

/**
 * @swagger
 * /orders:
 *   get:
 *     summary: Get user's orders
 *     tags: [Orders]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: List of user's orders
 */
app.get('/orders', verifyToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT o.*, os.status_code FROM "order" o JOIN order_status_code os ON o.status_code_id = os.id WHERE o.customer_id = $1 ORDER BY o.created_at DESC',
      [req.userId]
    );
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching orders', error: error.message });
  }
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));