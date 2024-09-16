// app.js
const express = require('express');
const swaggerJsdoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const { OAuth2Client } = require('google-auth-library');
const bcrypt = require('bcrypt');
require('dotenv').config();

const app = express();
app.use(express.json());

// PostgreSQL connection
const pool = new Pool({
  connectionString: process.env.POSTGRES_URL,
});

// Google OAuth client
const oauth2Client = new OAuth2Client(
  process.env.AUTH_GOOGLE_ID,
  process.env.AUTH_GOOGLE_SECRET,
  `${process.env.PUBLIC_SERVER_URL}/auth/google/callback`
);

// Swagger definition
const swaggerOptions = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'Comprehensive E-commerce API',
      version: '1.0.0',
      description: 'API for an e-commerce platform with Google OAuth',
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

// Middleware to check if user is admin
const isAdmin = async (req, res, next) => {
  try {
    const result = await pool.query('SELECT is_admin FROM customer WHERE id = $1', [req.userId]);
    if (result.rows[0].is_admin) {
      next();
    } else {
      res.status(403).send({ message: 'Requires admin privileges' });
    }
  } catch (error) {
    res.status(500).send({ message: 'Error checking admin status' });
  }
};

// Authentication APIs

/**
 * @swagger
 * /auth/google:
 *   get:
 *     summary: Initiate Google OAuth flow
 *     tags: [Authentication]
 *     responses:
 *       302:
 *         description: Redirects to Google OAuth page
 */
app.get('/auth/google', (req, res) => {
  const url = oauth2Client.generateAuthUrl({
    access_type: 'offline',
    scope: ['https://www.googleapis.com/auth/userinfo.profile', 'https://www.googleapis.com/auth/userinfo.email']
  });
  res.redirect(url);
});

/**
 * @swagger
 * /auth/google/callback:
 *   get:
 *     summary: Handle Google OAuth callback
 *     tags: [Authentication]
 *     parameters:
 *       - in: query
 *         name: code
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Authentication successful
 *       400:
 *         description: Authentication failed
 */
app.get('/auth/google/callback', async (req, res) => {
  const { code } = req.query;
  try {
    const { tokens } = await oauth2Client.getToken(code);
    oauth2Client.setCredentials(tokens);

    const ticket = await oauth2Client.verifyIdToken({
      idToken: tokens.id_token,
      audience: process.env.AUTH_GOOGLE_ID,
    });

    const payload = ticket.getPayload();
    const { sub: googleId, email, name } = payload;

    let result = await pool.query('SELECT * FROM customer WHERE google_id = $1', [googleId]);
    let user;

    if (result.rows.length === 0) {
      result = await pool.query(
        'INSERT INTO customer (google_id, email_address, first_name, last_name) VALUES ($1, $2, $3, $4) RETURNING *',
        [googleId, email, name.split(' ')[0], name.split(' ')[1] || '']
      );
      user = result.rows[0];
    } else {
      user = result.rows[0];
    }

    const token = jwt.sign({ id: user.id }, process.env.AUTH_SECRET, { expiresIn: '1h' });
    res.json({ auth: true, token });
  } catch (error) {
    res.status(400).json({ message: 'Authentication failed', error: error.message });
  }
});

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
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO customer (email_address, first_name, last_name) VALUES ($1, $2, $3) RETURNING id',
      [email, firstName, lastName]
    );
    await pool.query(
      'INSERT INTO customer_login (customer_id, password_hash) VALUES ($1, $2)',
      [result.rows[0].id, hashedPassword]
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
    if (result.rows.length > 0 && await bcrypt.compare(password, result.rows[0].password_hash)) {
      const token = jwt.sign({ id: result.rows[0].id }, process.env.AUTH_SECRET, { expiresIn: '1h' });
      res.json({ auth: true, token });
    } else {
      res.status(401).json({ message: 'Invalid credentials' });
    }
  } catch (error) {
    res.status(500).json({ message: 'Login failed', error: error.message });
  }
});

// User Profile APIs

/**
 * @swagger
 * /user/profile:
 *   get:
 *     summary: Get user profile
 *     tags: [User Profile]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: User profile
 */
app.get('/user/profile', verifyToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, email_address, first_name, last_name, created_at FROM customer WHERE id = $1', [req.userId]);
    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching profile', error: error.message });
  }
});

/**
 * @swagger
 * /user/profile:
 *   put:
 *     summary: Update user profile
 *     tags: [User Profile]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               firstName:
 *                 type: string
 *               lastName:
 *                 type: string
 *               email:
 *                 type: string
 *     responses:
 *       200:
 *         description: Profile updated successfully
 */
app.put('/user/profile', verifyToken, async (req, res) => {
  const { firstName, lastName, email } = req.body;
  try {
    await pool.query(
      'UPDATE customer SET first_name = $1, last_name = $2, email_address = $3 WHERE id = $4',
      [firstName, lastName, email, req.userId]
    );
    res.json({ message: 'Profile updated successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Error updating profile', error: error.message });
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
 *       - in: query
 *         name: category
 *         schema:
 *           type: string
 *         description: Filter by category
 *     responses:
 *       200:
 *         description: List of products
 */
app.get('/products', async (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 10;
  const offset = (page - 1) * limit;
  const category = req.query.category;

  try {
    let query = 'SELECT p.*, pc.name as category_name FROM product p JOIN product_category pc ON p.category_id = pc.id';
    let countQuery = 'SELECT COUNT(*) FROM product p';
    const queryParams = [];

    if (category) {
      query += ' WHERE pc.name = $1';
      countQuery += ' JOIN product_category pc ON p.category_id = pc.id WHERE pc.name = $1';
      queryParams.push(category);
    }

    query += ' LIMIT $' + (queryParams.length + 1) + ' OFFSET $' + (queryParams.length + 2);
    queryParams.push(limit, offset);

    const result = await pool.query(query, queryParams);
    const countResult = await pool.query(countQuery, category ? [category] : []);
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

// ... (previous product endpoints remain the same)

// Review APIs

/**
 * @swagger
 * /products/{id}/reviews:
 *   post:
 *     summary: Add a review for a product
 *     tags: [Reviews]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - rating
 *               - comment
 *             properties:
 *               rating:
 *                 type: integer
 *               comment:
 *                 type: string
 *     responses:
 *       201:
 *         description: Review added successfully
 */
app.post('/products/:id/reviews', verifyToken, async (req, res) => {
  const { rating, comment } = req.body;
  const productId = req.params.id;
  try {
    await pool.query(
      'INSERT INTO product_review (product_id, customer_id, rating, comment) VALUES ($1, $2, $3, $4)',
      [productId, req.userId, rating, comment]
    );
    res.status(201).json({ message: 'Review added successfully' });
  } catch (error) {
    res.status(400).json({ message: 'Error adding review', error: error.message });
  }
});

/**
 * @swagger
 * /products/{id}/reviews:
 *   get:
 *     summary: Get reviews for a product
 *     tags: [Reviews]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: List of reviews for the product
 */
app.get('/products/:id/reviews', async (req, res) => {
  const productId = req.params.id;
  try {
    const result = await pool.query(
      'SELECT pr.*, c.first_name, c.last_name FROM product_review pr JOIN customer c ON pr.customer_id = c.id WHERE pr.product_id = $1 ORDER BY pr.created_at DESC',
      [productId]
    );
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching reviews', error: error.message });
  }
});

// Wishlist APIs

/**
 * @swagger
 * /wishlist:
 *   get:
 *     summary: Get user's wishlist
 *     tags: [Wishlist]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: User's wishlist
 */
app.get('/wishlist', verifyToken, async (req, res) => {
    try {
      const result = await pool.query(
        'SELECT p.* FROM wishlist w JOIN product p ON w.product_id = p.id WHERE w.customer_id = $1',
        [req.userId]
      );
      res.json(result.rows);
    } catch (error) {
      res.status(500).json({ message: 'Error fetching wishlist', error: error.message });
    }
  });
  
  /**
   * @swagger
   * /wishlist/{productId}:
   *   post:
   *     summary: Add product to wishlist
   *     tags: [Wishlist]
   *     security:
   *       - bearerAuth: []
   *     parameters:
   *       - in: path
   *         name: productId
   *         required: true
   *         schema:
   *           type: integer
   *     responses:
   *       201:
   *         description: Product added to wishlist
   */
  app.post('/wishlist/:productId', verifyToken, async (req, res) => {
    const productId = req.params.productId;
    try {
      await pool.query(
        'INSERT INTO wishlist (customer_id, product_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
        [req.userId, productId]
      );
      res.status(201).json({ message: 'Product added to wishlist' });
    } catch (error) {
      res.status(400).json({ message: 'Error adding to wishlist', error: error.message });
    }
  });
  
  /**
   * @swagger
   * /wishlist/{productId}:
   *   delete:
   *     summary: Remove product from wishlist
   *     tags: [Wishlist]
   *     security:
   *       - bearerAuth: []
   *     parameters:
   *       - in: path
   *         name: productId
   *         required: true
   *         schema:
   *           type: integer
   *     responses:
   *       200:
   *         description: Product removed from wishlist
   */
  app.delete('/wishlist/:productId', verifyToken, async (req, res) => {
    const productId = req.params.productId;
    try {
      await pool.query(
        'DELETE FROM wishlist WHERE customer_id = $1 AND product_id = $2',
        [req.userId, productId]
      );
      res.json({ message: 'Product removed from wishlist' });
    } catch (error) {
      res.status(400).json({ message: 'Error removing from wishlist', error: error.message });
    }
  });
  
  // Cart APIs
  
  /**
   * @swagger
   * /cart:
   *   get:
   *     summary: Get user's cart
   *     tags: [Cart]
   *     security:
   *       - bearerAuth: []
   *     responses:
   *       200:
   *         description: User's cart
   */
  app.get('/cart', verifyToken, async (req, res) => {
    try {
      const result = await pool.query(
        'SELECT c.*, p.name, p.price FROM cart c JOIN product p ON c.product_id = p.id WHERE c.customer_id = $1',
        [req.userId]
      );
      res.json(result.rows);
    } catch (error) {
      res.status(500).json({ message: 'Error fetching cart', error: error.message });
    }
  });
  
  /**
   * @swagger
   * /cart:
   *   post:
   *     summary: Add product to cart
   *     tags: [Cart]
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
   *         description: Product added to cart
   */
  app.post('/cart', verifyToken, async (req, res) => {
    const { productId, quantity } = req.body;
    try {
      await pool.query(
        'INSERT INTO cart (customer_id, product_id, quantity) VALUES ($1, $2, $3) ON CONFLICT (customer_id, product_id) DO UPDATE SET quantity = cart.quantity + $3',
        [req.userId, productId, quantity]
      );
      res.status(201).json({ message: 'Product added to cart' });
    } catch (error) {
      res.status(400).json({ message: 'Error adding to cart', error: error.message });
    }
  });
  
  /**
   * @swagger
   * /cart/{productId}:
   *   delete:
   *     summary: Remove product from cart
   *     tags: [Cart]
   *     security:
   *       - bearerAuth: []
   *     parameters:
   *       - in: path
   *         name: productId
   *         required: true
   *         schema:
   *           type: integer
   *     responses:
   *       200:
   *         description: Product removed from cart
   */
  app.delete('/cart/:productId', verifyToken, async (req, res) => {
    const productId = req.params.productId;
    try {
      await pool.query(
        'DELETE FROM cart WHERE customer_id = $1 AND product_id = $2',
        [req.userId, productId]
      );
      res.json({ message: 'Product removed from cart' });
    } catch (error) {
      res.status(400).json({ message: 'Error removing from cart', error: error.message });
    }
  });
  
  // Order APIs
  
  /**
   * @swagger
   * /orders:
   *   post:
   *     summary: Create a new order
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
   *               - shippingAddress
   *             properties:
   *               shippingAddress:
   *                 type: string
   *     responses:
   *       201:
   *         description: Order created successfully
   */
  app.post('/orders', verifyToken, async (req, res) => {
    const { shippingAddress } = req.body;
    const client = await pool.connect();
  
    try {
      await client.query('BEGIN');
  
      // Create order
      const orderResult = await client.query(
        'INSERT INTO customer_order (customer_id, status, shipping_address) VALUES ($1, $2, $3) RETURNING id',
        [req.userId, 'Pending', shippingAddress]
      );
      const orderId = orderResult.rows[0].id;
  
      // Get cart items
      const cartItems = await client.query(
        'SELECT product_id, quantity FROM cart WHERE customer_id = $1',
        [req.userId]
      );
  
      // Add order items
      for (const item of cartItems.rows) {
        await client.query(
          'INSERT INTO order_item (order_id, product_id, quantity) VALUES ($1, $2, $3)',
          [orderId, item.product_id, item.quantity]
        );
      }
  
      // Clear cart
      await client.query('DELETE FROM cart WHERE customer_id = $1', [req.userId]);
  
      await client.query('COMMIT');
      res.status(201).json({ message: 'Order created successfully', orderId });
    } catch (error) {
      await client.query('ROLLBACK');
      res.status(400).json({ message: 'Error creating order', error: error.message });
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
        'SELECT * FROM customer_order WHERE customer_id = $1 ORDER BY created_at DESC',
        [req.userId]
      );
      res.json(result.rows);
    } catch (error) {
      res.status(500).json({ message: 'Error fetching orders', error: error.message });
    }
  });
  
  /**
   * @swagger
   * /orders/{orderId}:
   *   get:
   *     summary: Get order details
   *     tags: [Orders]
   *     security:
   *       - bearerAuth: []
   *     parameters:
   *       - in: path
   *         name: orderId
   *         required: true
   *         schema:
   *           type: integer
   *     responses:
   *       200:
   *         description: Order details
   */
  app.get('/orders/:orderId', verifyToken, async (req, res) => {
    const orderId = req.params.orderId;
    try {
      const orderResult = await pool.query(
        'SELECT * FROM customer_order WHERE id = $1 AND customer_id = $2',
        [orderId, req.userId]
      );
      if (orderResult.rows.length === 0) {
        return res.status(404).json({ message: 'Order not found' });
      }
  
      const itemsResult = await pool.query(
        'SELECT oi.*, p.name, p.price FROM order_item oi JOIN product p ON oi.product_id = p.id WHERE oi.order_id = $1',
        [orderId]
      );
  
      res.json({
        order: orderResult.rows[0],
        items: itemsResult.rows
      });
    } catch (error) {
      res.status(500).json({ message: 'Error fetching order details', error: error.message });
    }
  });
  
  // Payment APIs (simplified, in real-world scenario, integrate with a payment gateway)
  
  /**
   * @swagger
   * /orders/{orderId}/pay:
   *   post:
   *     summary: Process payment for an order
   *     tags: [Payments]
   *     security:
   *       - bearerAuth: []
   *     parameters:
   *       - in: path
   *         name: orderId
   *         required: true
   *         schema:
   *           type: integer
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             type: object
   *             required:
   *               - paymentMethod
   *             properties:
   *               paymentMethod:
   *                 type: string
   *     responses:
   *       200:
   *         description: Payment processed successfully
   */
  app.post('/orders/:orderId/pay', verifyToken, async (req, res) => {
    const orderId = req.params.orderId;
    const { paymentMethod } = req.body;
  
    try {
      // Check if order exists and belongs to the user
      const orderResult = await pool.query(
        'SELECT * FROM customer_order WHERE id = $1 AND customer_id = $2',
        [orderId, req.userId]
      );
      if (orderResult.rows.length === 0) {
        return res.status(404).json({ message: 'Order not found' });
      }
  
      // In a real-world scenario, integrate with a payment gateway here
  
      // Update order status
      await pool.query(
        'UPDATE customer_order SET status = $1, payment_method = $2 WHERE id = $3',
        ['Paid', paymentMethod, orderId]
      );
  
      res.json({ message: 'Payment processed successfully' });
    } catch (error) {
      res.status(500).json({ message: 'Error processing payment', error: error.message });
    }
  });
  
  // Start the server
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
  });