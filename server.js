require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt'); // Import bcrypt
const jwt = require('jsonwebtoken')
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const stripe = require('stripe')('sk_test_51OgqkWIPN9UEEGy8N8g88e19kSPmWuRGGTWpsxXrs5392bbvHoKXS5X5kW55iqACWaxoE4rTYJsH8BUy9V3vJLN800qJdYEk71');
const bodyParser = require('body-parser');
const nodemailer = require('nodemailer')
const crypto = require('crypto');


const app = express();
app.use(bodyParser.json({
    verify: (req, res, buf) => {
        if (req.originalUrl.startsWith('/stripe-update')) {
            req.rawBody = buf.toString();
        }
    }
}));

app.use(cookieParser()); // Use cookie-parser middleware
const corsOptions = {
    origin: 'https://profitarbleweb.onrender.com',  // Only allow requests from this origin
    optionsSuccessStatus: 200,
    credentials: true
};

app.use(cors(corsOptions));
app.use(express.json());

const apiLimiter = rateLimit({
    windowMs: 1000, // 1 second
    max: 1, // limit each IP to 1 request per windowMs
    message: "Too many requests, please try again later.",
});

let transporter = nodemailer.createTransport({
    host: "smtp.office365.com",
    port: 587,
    secure: false, // true for 465, false for other ports
    auth: {
        user: "profitarbtest@outlook.com", // your Outlook email address
        pass: "Giratina2001!", // your app password
    },
});

/* const db = new Pool({
    user: 'postgres',    // Replace with your PostgreSQL username
    host: 'localhost',        // Replace with your PostgreSQL server address
    database: 'Arbs', // Replace with your PostgreSQL database name
    password: 'Giratina2001!', // Replace with your PostgreSQL password
    port: 5432                // Replace with your PostgreSQL port, if different
});

const db = new Pool({
    user: 'postgres',
    host: 'localhost',
    database: 'Authentication',
    password: 'Giratina2001!',
    port: 5432
}); */
/* const db = new Pool({
    user: 'postgres',
    host: 'localhost',
    database: 'UserArbs',
    password: 'Giratina2001!',
    port: 5432
}); */
const db = new Pool ({
    user: process.env.DATABASE_USER,
    host: process.env.DATABASE_HOST,
    database: process.env.DATABASE_NAME,
    password: process.env.DATABASE_PASSWORD,
    port: 5432,
    ssl: {
        rejectUnauthorized: false
    }
})
app.get('/api/user-arbs', async (req, res) => {
    const { authorization } = req.headers;
    if (!authorization) {
        return res.status(401).json({ error: 'No authorization token provided' });
    }
    const token = authorization.split(' ')[1];
    if (!token) {
        return res.status(401).json({ error: 'Malformed token' });
    }
    try {
        const decoded = jwt.verify(token, process.env.JWT_KEY);
        const username = decoded.username;

        const userArbsQuery = 'SELECT Arbs FROM UserArbs WHERE "User" = $1';
        const result = await db.query(userArbsQuery, [username]);

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'No data found for user' });
        }

        res.json(result.rows[0].arbs);
    } catch (error) {
        console.error('Error fetching user arbs:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});
app.post('/api/update-user-arbs', async (req, res) => {
    const { authorization } = req.headers;
    if (!authorization) {
        return res.status(401).send('Authorization header is missing');
    }

    const token = authorization.split(' ')[1];
    if (!token) {
        return res.status(401).send('Authorization token is malformed');
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_KEY);
        const username = decoded.username;

        const arbs = req.body;
        const updateQuery = 'UPDATE UserArbs SET Arbs = $1 WHERE "User" = $2';
        await db.query(updateQuery, [JSON.stringify(arbs), username]);

        res.send('Arbs updated successfully');
    } catch (error) {
        console.error('Error updating arbs:', error);
        res.status(500).send('Failed to update arbs');
    }
});
app.post('/create-checkout-session', async (req, res) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.sendStatus(401);

    jwt.verify(token, process.env.JWT_KEY, async (err, user) => {
        if (err) return res.sendStatus(403);
        
        const userId = user.username;

        try {
            // Fetch user email from the database
            const userQuery = `
                SELECT email
                FROM users 
                WHERE username = $1;
            `;
            const userData = await db.query(userQuery, [userId]);

            if (userData.rows.length === 0) {
                // No user found with this username
                return res.status(404).send('User not recognized');
            }

            const userEmail = userData.rows[0].email;

            const session = await stripe.checkout.sessions.create({
                payment_method_types: ['card', 'paypal'],
                line_items: [{
                    price: 'price_1OmPa9IPN9UEEGy8IZF9grmN',
                    quantity: 1,
                }],
                mode: 'subscription',
                success_url: `${req.headers.origin}/success?session_id={CHECKOUT_SESSION_ID}`,
                cancel_url: `${req.headers.origin}/cancel`,
                client_reference_id: userId, // Securely pass the user ID
                customer_email: userEmail // Prefill the email field
            });

            res.json({ url: session.url });
        } catch (error) {
            res.status(500).send({ error: error.message });
        }
    });
});
app.post('/create-checkout-session-month', async (req, res) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.sendStatus(401);

    jwt.verify(token, process.env.JWT_KEY, async (err, user) => {
        if (err) return res.sendStatus(403);
        userId = user.username
        try {
            const session = await stripe.checkout.sessions.create({
                payment_method_types: ['card', 'paypal'],
                line_items: [{
                    price: 'price_1PAzjiIPN9UEEGy8KKf5GUWO',
                    quantity: 1,
                }],
                mode: 'subscription',
                success_url: `${req.headers.origin}/freeTrial`,
                cancel_url: `${req.headers.origin}/cancel`,
                client_reference_id: userId, // Securely pass the user ID
            });

            res.json({ url: session.url });
        } catch (error) {
            res.status(500).send({ error: error.message });
        }
    })
});
app.post('/stripe-update', async (req, res) => {
    const sig = req.headers['stripe-signature'];
    let event;
    try {
        event = stripe.webhooks.constructEvent(req.rawBody, sig, 'whsec_35b859637e0b5e9b978bf8f74e35cde5cfdfd7e01a8512ef8833844a9d667bf9');
        eventData = event.data.object
        if (event.type === 'checkout.session.completed') {
            const subscriptionId = eventData.subscription;
            const subscription = await stripe.subscriptions.retrieve(subscriptionId);
            const priceId = subscription.items.data[0].price.id;
            console.log('Price ID:', priceId);
            const customerId = eventData.customer;
            const username = eventData.client_reference_id;
            const expirationDate = new Date();
            if (priceId === "price_1OmPa9IPN9UEEGy8IZF9grmN") {
                expirationDate.setDate(expirationDate.getDate() + 7);
            } else if (priceId === "price_1PAzjiIPN9UEEGy8KKf5GUWO") {
                expirationDate.setDate(expirationDate.getDate() + 30);
            }

            const formattedExpDate = expirationDate.toISOString();
            const insertOrUpdateUserQuery = `
                        UPDATE users 
                        SET proVersion = TRUE, proVersionExpDate = $2, stripeCustomerId = $1
                        WHERE username = $3
                        RETURNING *;`;

            const result = await db.query(insertOrUpdateUserQuery, [customerId, formattedExpDate, username]);
            if (result.rows.length > 0) {
                console.log('Subscription created and user updated:', result.rows[0]);
            } else {
                console.log('No user found with the given username:', username);
            }
        }
        if (event.type === 'invoice.payment_succeeded') {
            const customerId = event.data.object.customer;
            const subscriptionId = event.data.object.subscription;
            const subscription = await stripe.subscriptions.retrieve(subscriptionId);
            const priceId = subscription.items.data[0].price.id;
            console.log('Price ID:', priceId);  // Log to verify price ID

            const newExpDate = new Date();
            if (priceId === "price_1OmPa9IPN9UEEGy8IZF9grmN") {
                newExpDate.setDate(newExpDate.getDate() + 7);
            } else if (priceId === "price_1PAzjiIPN9UEEGy8KKf5GUWO") {
                newExpDate.setDate(newExpDate.getDate() + 30);
            }

            const formattedExpDate = newExpDate.toISOString();
            const updateQuery = `
                UPDATE users 
                SET proVersionExpDate = $1 
                WHERE stripeCustomerId = $2
                RETURNING *;`;

            try {
                const result = await db.query(updateQuery, [formattedExpDate, customerId]);
                if (result.rows.length > 0) {
                    console.log('Updated user:', result.rows[0]);
                } else {
                    console.log('No user found with the given stripeCustomerId');
                }
            } catch (err) {
                console.error('Database update error:', err);
            }
        }
        if (event.type === 'invoice.payment_failed') {
            const customerId = event.data.object.customer;
            const updateQuery = `
                UPDATE users 
                SET proVersion = FALSE, proVersionExpDate = NULL
                WHERE stripeCustomerId = $1
                RETURNING *;`;

            try {
                const result = await db.query(updateQuery, [customerId]);
                if (result.rows.length > 0) {
                    console.log('Subscription marked as past_due:', result.rows[0]);
                } else {
                    console.log('No user found with the given stripeCustomerId');
                }
            } catch (err) {
                console.error('Database update error:', err);
            }
        }
        res.json({ received: true });

    } catch (err) {
        console.error(`Webhook Error: ${err.message}`);
        res.status(400).send(`Webhook Error: ${err.message}`);
    }
});
app.post('/api/cancel-subscription', async (req, res) => {
    const { username } = req.body;

    if (!username) {
        return res.status(400).send('Username is required');
    }

    try {
        const userQuery = `
            SELECT stripeCustomerId
            FROM users 
            WHERE username = $1;
        `;
        const userResult = await db.query(userQuery, [username]);

        if (userResult.rows.length === 0) {
            return res.status(404).send('User not found');
        }

        const stripeCustomerId = userResult.rows[0].stripecustomerid;
        const subscriptions = await stripe.subscriptions.list({
            customer: stripeCustomerId,
            status: 'active',
            limit: 1,
        });

        if (subscriptions.data.length === 0) {
            return res.status(404).send('No active subscription found for user');
        }

        const subscriptionId = subscriptions.data[0].id;
        await stripe.subscriptions.cancel(subscriptionId);


        const updateQuery = `
            UPDATE users 
            SET proVersion = FALSE
            WHERE username = $1
            RETURNING *;`;

        const updateResult = await db.query(updateQuery, [username]);
        if (updateResult.rows.length > 0) {
            console.log('Subscription cancelled and user updated:', updateResult.rows[0]);
            res.json({ message: 'Subscription cancelled successfully' });
        } else {
            console.log('Failed to update user after subscription cancellation');
            res.status(500).send('Failed to update user');
        }
    } catch (err) {
        console.error('Error handling subscription cancellation:', err);
        res.status(500).send(err.message);
    }
});
app.post('/api/save-arb', async (req, res) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) return res.sendStatus(401);

    jwt.verify(token, process.env.JWT_KEY, async (err, user) => {
        if (err) return res.sendStatus(403);

        try {
            const { entry } = req.body;
            const userCheckQuery = `
                SELECT * FROM UserArbs WHERE "User" = $1;
            `;
            const userResult = await db.query(userCheckQuery, [user.username]);

            if (userResult.rows.length > 0) {
                // User exists, load current arbs and update them
                let currentArbs = userResult.rows[0].arbs;



                // Ensure currentArbs is properly parsed as an array
                if (typeof currentArbs === 'string') {
                    currentArbs = JSON.parse(currentArbs);
                } else if (!Array.isArray(currentArbs)) {
                    currentArbs = [];
                }

                // Add the new entry to the current arbs
                const updatedArbs = [...currentArbs, entry];

                const updateArbsQuery = `
                    UPDATE UserArbs
                    SET arbs = $2
                    WHERE "User" = $1;
                `;
                await db.query(updateArbsQuery, [user.username, JSON.stringify(updatedArbs)]);
            } else {
                // User does not exist, insert new row
                const insertUserQuery = `
                    INSERT INTO UserArbs ("User", arbs)
                    VALUES ($1, $2);
                `;
                await db.query(insertUserQuery, [user.username, JSON.stringify([entry])]);
            }

            res.status(200).send('Arb saved successfully');
        } catch (dbError) {
            console.error("Database error:", dbError);
            res.status(500).send(dbError.message);
        }
    });
});


app.get('/api/matches', (req, res) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) return res.sendStatus(401);

    jwt.verify(token, process.env.JWT_KEY, async (err, user) => {
        if (err) return res.sendStatus(403);

        try {
            // Check user's trial and pro status
            const userQuery = `
                SELECT freeTrial, freeTrialExpDate, proVersion, proVersionExpDate 
                FROM users 
                WHERE username = $1;
            `;
            const userResult = await db.query(userQuery, [user.username]);
            const userData = userResult.rows[0];
            const isFreeTrialExpired = userData && userData.freetrial && new Date(userData.freetrialexpdate) > new Date();
            const isProVersionActive = userData && new Date(userData.proversionexpdate) > new Date();

            db.query("SELECT Match, Arbs, Links FROM matches", (err, matchResult) => {
                if (err) {
                    res.status(500).send(err.message);
                    return;
                }

                let modifiedResult = matchResult.rows;
                if (!isProVersionActive && isFreeTrialExpired) {
                    modifiedResult = modifiedResult.map(match => ({
                        ...match,
                        arbs: match.arbs.map(arb => {
                            if (arb["Profit"] > 1.5) {
                                return { "Profit": arb["Profit"], locked: true };
                            }
                            return arb;
                        })
                    }));
                }
                res.json(modifiedResult);
            });
        } catch (dbError) {
            res.status(500).send(dbError.message);
        }
    });
});
app.get('/api/username', (req, res) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) return res.sendStatus(401);

    jwt.verify(token, process.env.JWT_KEY, (err, user) => {
        if (err) return res.sendStatus(403);

        res.json({ username: user.username });
    });
});
app.post('/api/signup', async (req, res) => {
    const { name, surname, username, email, password } = req.body;

    try {
        // Check if a user with the same email or username already exists
        const checkUser = await db.query('SELECT * FROM users WHERE email = $1 OR username = $2', [email, username]);

        if (checkUser.rows.length > 0) {
            if (checkUser.rows[0].email === email) {
                return res.status(409).send('Email already exists');
            } else if (checkUser.rows[0].username === username) {
                return res.status(409).send('Username already exists');
            }
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const verificationToken = crypto.randomBytes(32).toString('hex');
        const insertQuery = `
            INSERT INTO users (name, surname, username, email, password, verification_token)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING *;`;
        const newUser = await db.query(insertQuery, [name, surname, username, email, hashedPassword, verificationToken]);

        // Send verification email
        const verificationUrl = `https://profitarble.onrender.com/api/verify-email?token=${verificationToken}`;
        const mailOptions = {
            from: '"Your App Name" <profitarbtest@outlook.com>',
            to: email,
            subject: "Email Verification",
            text: `Please verify your email by clicking the following link: ${verificationUrl}`,
            html: `<p>Please verify your email by clicking the following link: <a href="${verificationUrl}">${verificationUrl}</a></p>`
        };

        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                return console.log(error);
            }
            console.log('Message sent: %s', info.messageId);
        });

        res.status(201).json(newUser.rows[0]);
    } catch (err) {
        res.status(500).send(err.message);
    }
});
app.get('/api/verify-email', async (req, res) => {
    const { token } = req.query;

    try {
        const userQuery = await db.query('SELECT * FROM users WHERE verification_token = $1', [token]);

        if (userQuery.rows.length === 0) {
            return res.status(400).send('Invalid token');
        }

        await db.query('UPDATE users SET is_verified = TRUE, verification_token = NULL WHERE verification_token = $1', [token]);

        res.status(200).send(`
            <html>
            <head>
                <script type="text/javascript">
                    alert('Email verified successfully');
                    window.location.href = 'https://profitarbleweb.onrender.com/login';
                </script>
            </head>
            <body>
            </body>
            </html>
        `);
    } catch (err) {
        res.status(500).send(err.message);
    }
});

app.post('/api/start-free-trial', async (req, res) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) return res.sendStatus(401);

    jwt.verify(token, process.env.JWT_KEY, async (err, user) => {
        if (err) return res.sendStatus(403);

        const username = user.username;
        const oneWeekFromNow = new Date();
        oneWeekFromNow.setDate(oneWeekFromNow.getDate() + 7);

        try {
            const updateQuery = `
                UPDATE users 
                SET freeTrial = TRUE, freeTrialExpDate = $1 
                WHERE username = $2
                RETURNING *;`;
            const updatedUser = await db.query(updateQuery, [oneWeekFromNow, username]);

            if (updatedUser.rows.length === 0) {
                // No user found with this username
                return res.status(404).send('User not found');
            }

            res.status(200).json(updatedUser.rows[0]);
        } catch (err) {
            res.status(500).send(err.message);
        }
    });
});
app.post('/api/start-paid-trial', async (req, res) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.sendStatus(401);

    jwt.verify(token, process.env.JWT_KEY, async (err, user) => {
        if (err) return res.sendStatus(403);

        const username = user.username;
        const userF = `
            SELECT email, stripeCustomerId
            FROM users 
            WHERE username = $1;
        `;
        const userData = await db.query(userF, [username]);
        const { paymentMethodId } = req.body;
        if (userData.rows.length === 0) {
            // No user found with this username
            return res.status(404).send('User not recognized');
        }
        try {
            let customer;
            if (userData.stripeCustomerId) {
                customer = await stripe.customers.retrieve(userData.stripeCustomerId);
            } else {
                customer = await stripe.customers.create({
                    email: userData.rows[0].email,
                    payment_method: paymentMethodId,
                    invoice_settings: {
                        default_payment_method: paymentMethodId,
                    },
                });
                const updateCustomerQuery = `UPDATE users SET stripeCustomerId = $1 WHERE username = $2`;
                await db.query(updateCustomerQuery, [customer.id, username]);
            }

            // Assuming you have a predefined price ID for the subscription
            const priceId = 'price_1OmPa9IPN9UEEGy8IZF9grmN';

            const subscription = await stripe.subscriptions.create({
                customer: customer.id,
                items: [{ price: priceId }],
                expand: ['latest_invoice.payment_intent'],
            });

            // Update your database to reflect the subscription's start
            const oneWeekFromNow = new Date();
            oneWeekFromNow.setDate(oneWeekFromNow.getDate() + 7); // Adjust based on your trial period
            const updateSubscriptionQuery = `
                UPDATE users 
                SET proVersion = TRUE, proVersionExpDate = $1 
                WHERE username = $2
                RETURNING *;`;
            const updatedUser = await db.query(updateSubscriptionQuery, [oneWeekFromNow, username]);

            res.status(200).json({
                subscriptionId: subscription.id,
                customer: customer.id,
                user: updatedUser.rows[0]
            });
        } catch (error) {
            console.log(error);
            res.status(500).send(error.message);
        }
    });
});
app.get('/api/user-trial-status', async (req, res) => {
    const { username } = req.query;

    if (!username) {
        return res.status(400).send('Username is required');
    }

    try {
        const userQuery = `
            SELECT freeTrial, freeTrialExpDate, proVersion, proVersionExpDate
            FROM users 
            WHERE username = $1;
        `;
        const result = await db.query(userQuery, [username]);

        if (result.rows.length === 0) {
            return res.status(404).send('User not found');
        }

        const user = result.rows[0];
        res.json({ freeTrial: user.freetrial, freeTrialExpDate: user.freetrialexpdate, proVersion: user.proversion, proVersionExpDate: user.proversionexpdate });
    } catch (err) {
        res.status(500).send(err.message);
    }
});

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        const userQuery = await db.query('SELECT * FROM users WHERE username = $1', [username]);

        if (userQuery.rows.length === 0) {
            return res.status(404).send('User not found');
        }

        const user = userQuery.rows[0];
        if (!user.is_verified) {
            return res.status(403).send('Email not verified');
        }

        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.status(401).send('Incorrect password');
        }

        const token = jwt.sign({ username: user.username }, process.env.JWT_KEY, { expiresIn: '48h' });

        res.status(200).json({ token: token });
    } catch (err) {
        res.status(500).send(err.message);
    }
});
app.post('/api/resend-verification-email', async (req, res) => {
    const { email } = req.body;

    try {
        const userQuery = await db.query('SELECT * FROM users WHERE email = $1', [email]);

        if (userQuery.rows.length === 0) {
            return res.status(404).send('User not found');
        }

        const user = userQuery.rows[0];
        if (user.is_verified) {
            return res.status(400).send('Email is already verified');
        }

        const verificationToken = crypto.randomBytes(32).toString('hex');
        await db.query('UPDATE users SET verification_token = $1 WHERE email = $2', [verificationToken, email]);

        const verificationUrl = `https://profitarble.onrender.com/api/verify-email?token=${verificationToken}`;
        const mailOptions = {
            from: '"Your App Name" <profitarbtest@outlook.com>',
            to: email,
            subject: "Email Verification",
            text: `Please verify your email by clicking the following link: ${verificationUrl}`,
            html: `<p>Please verify your email by clicking the following link: <a href="${verificationUrl}">${verificationUrl}</a></p>`
        };

        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                return console.log(error);
            }
            console.log('Message sent: %s', info.messageId);
        });

        res.status(200).send('Verification email resent successfully');
    } catch (err) {
        res.status(500).send(err.message);
    }
});
app.get('/api/get-email', async (req, res) => {
    const { username } = req.query;

    try {
        const userQuery = await db.query('SELECT email FROM users WHERE username = $1', [username]);

        if (userQuery.rows.length === 0) {
            return res.status(404).send('User not found');
        }

        const user = userQuery.rows[0];
        res.status(200).json({ email: user.email });
    } catch (err) {
        res.status(500).send(err.message);
    }
});


const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});

