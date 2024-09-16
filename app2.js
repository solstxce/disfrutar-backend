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

// Swagger configuration
const swaggerOptions = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'Enhanced E-commerce API',
      version: '1.1.0',
      description: 'Comprehensive API for an e-commerce platform with inventory control, user management, and additional features',
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

app.get('/auth/google', (req, res) => {
  const url = oauth2Client.generateAuthUrl({
    access_type: 'offline',
    scope: ['https://www.googleapis.com/auth/userinfo.profile', 'https://www.googleapis.com/auth/userinfo.email']
  });
  res.redirect(url);
});

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

app.get('/user/profile', verifyToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, email_address, first_name, last_name, created_at FROM customer WHERE id = $1', [req.userId]);
    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching profile', error: error.message });
  }
});

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

app.post('/products', verifyToken, isAdmin, async (req, res) => {
  const { name, description, price, category_id, stock_quantity } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO product (name, description, price, category_id, stock_quantity) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [name, description, price, category_id, stock_quantity]
    );
    res.status(201).json(result.rows[0]);
  } catch (error) {
    res.status(400).json({ message: 'Error adding product', error: error.message });
  }
});

app.put('/products/:id', verifyToken, isAdmin, async (req, res) => {
  const { id } = req.params;
  const { name, description, price, category_id, stock_quantity } = req.body;
  try {
    const result = await pool.query(
      'UPDATE product SET name = $1, description = $2, price = $3, category_id = $4, stock_quantity = $5 WHERE id = $6 RETURNING *',
      [name, description, price, category_id, stock_quantity, id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Product not found' });
    }
    res.json(result.rows[0]);
  } catch (error) {
    res.status(400).json({ message: 'Error updating product', error: error.message });
  }
});

app.delete('/products/:id', verifyToken, isAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query('DELETE FROM product WHERE id = $1 RETURNING *', [id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Product not found' });
    }
    res.json({ message: 'Product deleted successfully' });
  } catch (error) {
    res.status(400).json({ message: 'Error deleting product', error: error.message });
  }
});

app.patch('/products/:id/stock', verifyToken, isAdmin, async (req, res) => {
  const { id } = req.params;
  const { quantity } = req.body;
  try {
    const result = await pool.query(
      'UPDATE product SET stock_quantity = stock_quantity + $1 WHERE id = $2 RETURNING *',
      [quantity, id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Product not found' });
    }
    res.json(result.rows[0]);
  } catch (error) {
    res.status(400).json({ message: 'Error updating stock', error: error.message });
  }
});

// Review APIs

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


app.patch('/orders/:orderId/status', verifyToken, isAdmin, async (req, res) => {
  const { orderId } = req.params;
  const { status } = req.body;
  try {
    const result = await pool.query(
      'UPDATE customer_order SET status = $1 WHERE id = $2 RETURNING *',
      [status, orderId]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Order not found' });
    }
    res.json({ message: 'Order status updated', order: result.rows[0] });
  } catch (error) {
    res.status(400).json({ message: 'Error updating order status', error: error.message });
  }
});

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

app.get('/categories', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM product_category');
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching categories', error: error.message });
  }
});

app.post('/categories', verifyToken, isAdmin, async (req, res) => {
  const { name, description } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO product_category (name, description) VALUES ($1, $2) RETURNING *',
      [name, description]
    );
    res.status(201).json(result.rows[0]);
  } catch (error) {
    res.status(400).json({ message: 'Error adding category', error: error.message });
  }
});

// Search API
app.get('/search', async (req, res) => {
  const { query, page = 1, limit = 10 } = req.query;
  const offset = (page - 1) * limit;
  
  try {
    const searchQuery = `
      SELECT p.*, pc.name as category_name 
      FROM product p 
      JOIN product_category pc ON p.category_id = pc.id 
      WHERE p.name ILIKE $1 OR p.description ILIKE $1
      LIMIT $2 OFFSET $3
    `;
    const result = await pool.query(searchQuery, [`%${query}%`, limit, offset]);
    
    const countQuery = `
      SELECT COUNT(*) 
      FROM product 
      WHERE name ILIKE $1 OR description ILIKE $1
    `;
    const countResult = await pool.query(countQuery, [`%${query}%`]);
    
    const totalProducts = parseInt(countResult.rows[0].count);
    const totalPages = Math.ceil(totalProducts / limit);

    res.json({
      products: result.rows,
      currentPage: parseInt(page),
      totalPages: totalPages,
      totalProducts: totalProducts
    });
  } catch (error) {
    res.status(500).json({ message: 'Error searching products', error: error.message });
  }
});

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


// Wishlist APIs

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


app.post('/user/addresses', verifyToken, async (req, res) => {
  const { address_line1, address_line2, city, state, postal_code, country } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO customer_address (customer_id, address_line1, address_line2, city, state, postal_code, country) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *',
      [req.userId, address_line1, address_line2, city, state, postal_code, country]
    );
    res.status(201).json(result.rows[0]);
  } catch (error) {
    res.status(400).json({ message: 'Error adding address', error: error.message });
  }
});

app.get('/user/addresses', verifyToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM customer_address WHERE customer_id = $1', [req.userId]);
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching addresses', error: error.message });
  }
});

app.post('/coupons', verifyToken, isAdmin, async (req, res) => {
  const { code, discount_percent, valid_from, valid_to } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO coupon (code, discount_percent, valid_from, valid_to) VALUES ($1, $2, $3, $4) RETURNING *',
      [code, discount_percent, valid_from, valid_to]
    );
    res.status(201).json(result.rows[0]);
  } catch (error) {
    res.status(400).json({ message: 'Error creating coupon', error: error.message });
  }
});

app.post('/apply-coupon', verifyToken, async (req, res) => {
  const { code } = req.body;
  try {
    const result = await pool.query(
      'SELECT * FROM coupon WHERE code = $1 AND valid_from <= CURRENT_DATE AND valid_to >= CURRENT_DATE',
      [code]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Invalid or expired coupon' });
    }
    res.json({ message: 'Coupon applied successfully', discount: result.rows[0].discount_percent });
  } catch (error) {
    res.status(500).json({ message: 'Error applying coupon', error: error.message });
  }
});


// Product Rating API
app.get('/products/:id/rating', async (req, res) => {
  const productId = req.params.id;
  try {
    const result = await pool.query(
      'SELECT AVG(rating) as average_rating, COUNT(*) as review_count FROM product_review WHERE product_id = $1',
      [productId]
    );
    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching product rating', error: error.message });
  }
});


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

// New Cart APIs

// Update cart item quantity
app.put('/cart/:productId', verifyToken, async (req, res) => {
  const productId = req.params.productId;
  const { quantity } = req.body;
  try {
    const result = await pool.query(
      'UPDATE cart SET quantity = $1 WHERE customer_id = $2 AND product_id = $3 RETURNING *',
      [quantity, req.userId, productId]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Cart item not found' });
    }
    res.json({ message: 'Cart item quantity updated', item: result.rows[0] });
  } catch (error) {
    res.status(400).json({ message: 'Error updating cart item quantity', error: error.message });
  }
});

// Clear entire cart
app.delete('/cart', verifyToken, async (req, res) => {
  try {
    await pool.query('DELETE FROM cart WHERE customer_id = $1', [req.userId]);
    res.json({ message: 'Cart cleared successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Error clearing cart', error: error.message });
  }
});

app.get('/admin/sales-report', verifyToken, isAdmin, async (req, res) => {
  const { startDate, endDate } = req.query;
  try {
    const result = await pool.query(
      `SELECT p.id, p.name, SUM(oi.quantity) as total_sold, SUM(oi.quantity * p.price) as revenue
       FROM order_item oi
       JOIN product p ON oi.product_id = p.id
       JOIN customer_order co ON oi.order_id = co.id
       WHERE co.created_at BETWEEN $1 AND $2
       GROUP BY p.id, p.name
       ORDER BY revenue DESC`,
      [startDate, endDate]
    );
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ message: 'Error generating sales report', error: error.message });
  }
});

app.get('/admin/low-stock-alerts', verifyToken, isAdmin, async (req, res) => {
  const threshold = req.query.threshold || 10;
  try {
    const result = await pool.query(
      'SELECT id, name, stock_quantity FROM product WHERE stock_quantity <= $1 ORDER BY stock_quantity ASC',
      [threshold]
    );
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching low stock alerts', error: error.message });
  }
});

const PORT = process.env.PORT || 3005;

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});