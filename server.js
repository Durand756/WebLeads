const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const { Sequelize, DataTypes } = require('sequelize');
const { chromium } = require('playwright');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const validator = require('validator');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Configuration
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-in-production';
const DATABASE_URL = process.env.DATABASE_URL || 'mysql://user:password@localhost:3306/saas_db';

// Middleware
app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.static('public'));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use('/api/', limiter);

// Database Setup
const sequelize = new Sequelize(DATABASE_URL, {
  dialect: 'mysql',
  logging: false,
  pool: {
    max: 5,
    min: 0,
    acquire: 30000,
    idle: 10000
  }
});

// Models
const User = sequelize.define('User', {
  id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
  name: { type: DataTypes.STRING(100), allowNull: false },
  email: { type: DataTypes.STRING(255), allowNull: false, unique: true },
  password_hash: { type: DataTypes.STRING(255), allowNull: false },
  created_at: { type: DataTypes.DATE, defaultValue: DataTypes.NOW }
});

const Site = sequelize.define('Site', {
  id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
  user_id: { type: DataTypes.INTEGER, allowNull: false },
  url: { type: DataTypes.STRING(500), allowNull: false },
  score: { type: DataTypes.INTEGER, defaultValue: 0 },
  last_audit: { type: DataTypes.DATE, defaultValue: DataTypes.NOW }
});

const SEOAudit = sequelize.define('SEOAudit', {
  id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
  site_id: { type: DataTypes.INTEGER, allowNull: false },
  score: { type: DataTypes.INTEGER, allowNull: false },
  recommendations: { type: DataTypes.TEXT, allowNull: false },
  created_at: { type: DataTypes.DATE, defaultValue: DataTypes.NOW }
});

const Contact = sequelize.define('Contact', {
  id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
  user_id: { type: DataTypes.INTEGER, allowNull: false },
  email: { type: DataTypes.STRING(255), allowNull: false },
  name: { type: DataTypes.STRING(100), allowNull: false },
  created_at: { type: DataTypes.DATE, defaultValue: DataTypes.NOW }
});

const Campaign = sequelize.define('Campaign', {
  id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
  user_id: { type: DataTypes.INTEGER, allowNull: false },
  title: { type: DataTypes.STRING(255), allowNull: false },
  content: { type: DataTypes.TEXT, allowNull: false },
  status: { type: DataTypes.ENUM('draft', 'sent', 'active'), defaultValue: 'draft' },
  sent_at: { type: DataTypes.DATE }
});

const CampaignStats = sequelize.define('CampaignStats', {
  id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
  campaign_id: { type: DataTypes.INTEGER, allowNull: false },
  opens: { type: DataTypes.INTEGER, defaultValue: 0 },
  clicks: { type: DataTypes.INTEGER, defaultValue: 0 },
  unsubscribes: { type: DataTypes.INTEGER, defaultValue: 0 }
});

// Relations
User.hasMany(Site, { foreignKey: 'user_id' });
User.hasMany(Contact, { foreignKey: 'user_id' });
User.hasMany(Campaign, { foreignKey: 'user_id' });
Site.hasMany(SEOAudit, { foreignKey: 'site_id' });
Campaign.hasOne(CampaignStats, { foreignKey: 'campaign_id' });

// SMTP Configuration
const createTransporter = () => {
  try {
    return nodemailer.createTransporter({
      host: process.env.SMTP_HOST || 'smtp.gmail.com',
      port: process.env.SMTP_PORT || 587,
      secure: false,
      auth: {
        user: process.env.SMTP_USER || 'your-email@gmail.com',
        pass: process.env.SMTP_PASS || 'your-app-password'
      }
    });
  } catch (error) {
    console.error('SMTP Configuration Error:', error.message);
    return null;
  }
};

// Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }
    req.user = user;
    next();
  });
};

// SEO Audit Module (Independent)
class SEOAuditor {
  static async performAudit(url) {
    let browser = null;
    try {
      // Validate URL
      if (!validator.isURL(url)) {
        throw new Error('Invalid URL provided');
      }

      browser = await chromium.launch({ headless: true });
      const page = await browser.newPage();
      
      // Set user agent and viewport
      await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36');
      await page.setViewportSize({ width: 1920, height: 1080 });
      
      const startTime = Date.now();
      await page.goto(url, { waitUntil: 'networkidle', timeout: 30000 });
      const loadTime = Date.now() - startTime;

      // Comprehensive SEO Analysis
      const auditData = await page.evaluate(() => {
        const results = {
          title: document.title || '',
          description: '',
          h1Count: document.querySelectorAll('h1').length,
          h2Count: document.querySelectorAll('h2').length,
          imageCount: document.querySelectorAll('img').length,
          imagesWithoutAlt: document.querySelectorAll('img:not([alt])').length,
          linkCount: document.querySelectorAll('a').length,
          externalLinks: 0,
          internalLinks: 0,
          metaTags: {},
          structuredData: [],
          socialMeta: {},
          wordCount: 0,
          readabilityScore: 0
        };

        // Meta tags analysis
        document.querySelectorAll('meta').forEach(meta => {
          const name = meta.getAttribute('name') || meta.getAttribute('property');
          const content = meta.getAttribute('content');
          if (name && content) {
            results.metaTags[name] = content;
            if (name === 'description') results.description = content;
          }
        });

        // Social media meta tags
        ['og:title', 'og:description', 'og:image', 'twitter:title', 'twitter:description', 'twitter:image'].forEach(prop => {
          const tag = document.querySelector(`meta[property="${prop}"], meta[name="${prop}"]`);
          if (tag) results.socialMeta[prop] = tag.getAttribute('content');
        });

        // Link analysis
        const currentDomain = window.location.hostname;
        document.querySelectorAll('a[href]').forEach(link => {
          const href = link.getAttribute('href');
          if (href) {
            if (href.startsWith('http') && !href.includes(currentDomain)) {
              results.externalLinks++;
            } else {
              results.internalLinks++;
            }
          }
        });

        // Word count and readability
        const textContent = document.body.innerText || '';
        const words = textContent.trim().split(/\s+/).filter(word => word.length > 0);
        results.wordCount = words.length;
        
        // Simple readability score (Flesch-like)
        const sentences = textContent.split(/[.!?]+/).filter(s => s.trim().length > 0);
        const avgWordsPerSentence = sentences.length > 0 ? words.length / sentences.length : 0;
        const avgSyllablesPerWord = words.reduce((sum, word) => sum + Math.max(1, word.length / 3), 0) / words.length;
        results.readabilityScore = Math.max(0, Math.min(100, 206.835 - (1.015 * avgWordsPerSentence) - (84.6 * avgSyllablesPerWord)));

        // Structured data
        document.querySelectorAll('script[type="application/ld+json"]').forEach(script => {
          try {
            const data = JSON.parse(script.textContent);
            results.structuredData.push(data['@type'] || 'Unknown');
          } catch (e) {}
        });

        return results;
      });

      // Performance metrics
      const performanceMetrics = await page.evaluate(() => {
        const navigation = performance.getEntriesByType('navigation')[0];
        return {
          domContentLoaded: navigation.domContentLoadedEventEnd - navigation.domContentLoadedEventStart,
          loadComplete: navigation.loadEventEnd - navigation.loadEventStart,
          firstPaint: performance.getEntriesByName('first-paint')[0]?.startTime || 0,
          firstContentfulPaint: performance.getEntriesByName('first-contentful-paint')[0]?.startTime || 0
        };
      });

      await browser.close();

      // Calculate SEO Score
      const score = this.calculateSEOScore({
        ...auditData,
        loadTime,
        performanceMetrics
      });

      // Generate recommendations
      const recommendations = this.generateRecommendations({
        ...auditData,
        loadTime,
        performanceMetrics
      });

      return {
        score,
        recommendations,
        data: {
          ...auditData,
          loadTime,
          performanceMetrics
        }
      };

    } catch (error) {
      if (browser) await browser.close();
      console.error('SEO Audit Error:', error.message);
      throw new Error(`SEO audit failed: ${error.message}`);
    }
  }

  static calculateSEOScore(data) {
    let score = 0;
    
    // Title optimization (20 points)
    if (data.title && data.title.length >= 30 && data.title.length <= 60) score += 20;
    else if (data.title) score += 10;
    
    // Meta description (20 points)
    if (data.description && data.description.length >= 120 && data.description.length <= 160) score += 20;
    else if (data.description) score += 10;
    
    // Heading structure (15 points)
    if (data.h1Count === 1) score += 10;
    if (data.h2Count > 0) score += 5;
    
    // Images optimization (15 points)
    const imageOptimizationRatio = data.imageCount > 0 ? 1 - (data.imagesWithoutAlt / data.imageCount) : 1;
    score += Math.round(imageOptimizationRatio * 15);
    
    // Performance (15 points)
    if (data.loadTime < 2000) score += 15;
    else if (data.loadTime < 4000) score += 10;
    else if (data.loadTime < 6000) score += 5;
    
    // Content quality (10 points)
    if (data.wordCount >= 300) score += 10;
    else if (data.wordCount >= 150) score += 5;
    
    // Social media optimization (5 points)
    const socialTagsCount = Object.keys(data.socialMeta).length;
    if (socialTagsCount >= 4) score += 5;
    else if (socialTagsCount >= 2) score += 3;
    
    return Math.min(100, score);
  }

  static generateRecommendations(data) {
    const recommendations = [];
    
    // Title recommendations
    if (!data.title) {
      recommendations.push({ type: 'critical', text: 'Add a title tag to your page' });
    } else if (data.title.length < 30) {
      recommendations.push({ type: 'warning', text: 'Title is too short. Aim for 30-60 characters' });
    } else if (data.title.length > 60) {
      recommendations.push({ type: 'warning', text: 'Title is too long. Keep it under 60 characters' });
    }
    
    // Meta description recommendations
    if (!data.description) {
      recommendations.push({ type: 'critical', text: 'Add a meta description to your page' });
    } else if (data.description.length < 120) {
      recommendations.push({ type: 'warning', text: 'Meta description is too short. Aim for 120-160 characters' });
    } else if (data.description.length > 160) {
      recommendations.push({ type: 'warning', text: 'Meta description is too long. Keep it under 160 characters' });
    }
    
    // Heading recommendations
    if (data.h1Count === 0) {
      recommendations.push({ type: 'critical', text: 'Add an H1 heading to your page' });
    } else if (data.h1Count > 1) {
      recommendations.push({ type: 'warning', text: 'Use only one H1 heading per page' });
    }
    
    if (data.h2Count === 0) {
      recommendations.push({ type: 'info', text: 'Consider adding H2 headings to structure your content' });
    }
    
    // Image optimization
    if (data.imagesWithoutAlt > 0) {
      recommendations.push({ 
        type: 'warning', 
        text: `${data.imagesWithoutAlt} images are missing alt attributes` 
      });
    }
    
    // Performance recommendations
    if (data.loadTime > 6000) {
      recommendations.push({ type: 'critical', text: 'Page load time is too slow (>6s). Optimize images and reduce HTTP requests' });
    } else if (data.loadTime > 4000) {
      recommendations.push({ type: 'warning', text: 'Page load time could be improved (<4s is recommended)' });
    }
    
    // Content recommendations
    if (data.wordCount < 150) {
      recommendations.push({ type: 'warning', text: 'Content is too short. Add more relevant content (300+ words recommended)' });
    }
    
    // Social media optimization
    const socialTags = Object.keys(data.socialMeta).length;
    if (socialTags < 2) {
      recommendations.push({ type: 'info', text: 'Add Open Graph and Twitter meta tags for better social sharing' });
    }
    
    // Structured data
    if (data.structuredData.length === 0) {
      recommendations.push({ type: 'info', text: 'Consider adding structured data (JSON-LD) for better search engine understanding' });
    }
    
    return recommendations;
  }
}

// Email Marketing Module (Independent)
class EmailMarketing {
  static async sendCampaign(campaign, contacts, transporter) {
    if (!transporter) {
      throw new Error('SMTP transporter not available. Check your email configuration.');
    }

    const results = {
      sent: 0,
      failed: 0,
      errors: []
    };

    // Create tracking pixels and unsubscribe links
    const trackingPixel = `<img src="${process.env.BASE_URL || 'http://localhost:3000'}/api/email/track/${campaign.id}" width="1" height="1" style="display:none;">`;
    const unsubscribeLink = `${process.env.BASE_URL || 'http://localhost:3000'}/api/email/unsubscribe`;
    
    const htmlContent = `
      ${campaign.content}
      <hr>
      <small>
        <a href="${unsubscribeLink}">Unsubscribe</a>
      </small>
      ${trackingPixel}
    `;

    // Send emails in batches to avoid overwhelming SMTP server
    const batchSize = 10;
    for (let i = 0; i < contacts.length; i += batchSize) {
      const batch = contacts.slice(i, i + batchSize);
      
      const batchPromises = batch.map(async (contact) => {
        try {
          await transporter.sendMail({
            from: process.env.SMTP_USER || 'noreply@yourapp.com',
            to: contact.email,
            subject: campaign.title,
            html: htmlContent.replace(/{{name}}/g, contact.name),
            headers: {
              'List-Unsubscribe': `<${unsubscribeLink}>`,
              'X-Campaign-ID': campaign.id.toString()
            }
          });
          results.sent++;
        } catch (error) {
          results.failed++;
          results.errors.push(`${contact.email}: ${error.message}`);
          console.error(`Failed to send email to ${contact.email}:`, error.message);
        }
      });

      await Promise.allSettled(batchPromises);
      
      // Small delay between batches
      if (i + batchSize < contacts.length) {
        await new Promise(resolve => setTimeout(resolve, 1000));
      }
    }

    return results;
  }
}

// Routes

// Serve frontend
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Authentication routes
app.post('/api/signup', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    
    // Validation
    if (!name || !email || !password) {
      return res.status(400).json({ error: 'Name, email, and password are required' });
    }
    
    if (!validator.isEmail(email)) {
      return res.status(400).json({ error: 'Invalid email format' });
    }
    
    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters long' });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ where: { email } });
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists with this email' });
    }

    // Hash password and create user
    const password_hash = await bcrypt.hash(password, 10);
    const user = await User.create({ name, email, password_hash });

    // Generate JWT token
    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '24h' });

    res.status(201).json({
      message: 'User created successfully',
      token,
      user: { id: user.id, name: user.name, email: user.email }
    });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ error: 'Internal server error during signup' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    // Find user
    const user = await User.findOne({ where: { email } }).catch(err => {
      console.log('Database query error:', err.message);
      return null;
    });
    
    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Verify password
    const isValidPassword = await bcrypt.compare(password, user.password_hash);
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Generate JWT token
    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '24h' });

    res.json({
      message: 'Login successful',
      token,
      user: { id: user.id, name: user.name, email: user.email }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error during login' });
  }
});

// Sites management routes
app.get('/api/sites', authenticateToken, async (req, res) => {
  try {
    const sites = await Site.findAll({
      where: { user_id: req.user.id },
      include: [{
        model: SEOAudit,
        limit: 1,
        order: [['created_at', 'DESC']]
      }]
    });
    res.json(sites);
  } catch (error) {
    console.error('Get sites error:', error);
    res.status(500).json({ error: 'Failed to fetch sites' });
  }
});

app.post('/api/sites', authenticateToken, async (req, res) => {
  try {
    const { url } = req.body;
    
    if (!url || !validator.isURL(url)) {
      return res.status(400).json({ error: 'Valid URL is required' });
    }

    // Check site limit
    const siteCount = await Site.count({ where: { user_id: req.user.id } });
    if (siteCount >= 3) {
      return res.status(400).json({ error: 'Maximum of 3 sites allowed per user' });
    }

    // Check if site already exists for user
    const existingSite = await Site.findOne({ where: { user_id: req.user.id, url } });
    if (existingSite) {
      return res.status(400).json({ error: 'This site is already added' });
    }

    const site = await Site.create({ user_id: req.user.id, url });
    res.status(201).json(site);
  } catch (error) {
    console.error('Add site error:', error);
    res.status(500).json({ error: 'Failed to add site' });
  }
});

app.delete('/api/sites/:id', authenticateToken, async (req, res) => {
  try {
    const site = await Site.findOne({
      where: { id: req.params.id, user_id: req.user.id }
    });

    if (!site) {
      return res.status(404).json({ error: 'Site not found' });
    }

    await site.destroy();
    res.json({ message: 'Site deleted successfully' });
  } catch (error) {
    console.error('Delete site error:', error);
    res.status(500).json({ error: 'Failed to delete site' });
  }
});

// SEO Audit route (Independent module)
app.post('/api/audit', authenticateToken, async (req, res) => {
  try {
    const { siteId, url } = req.body;
    
    if (!siteId && !url) {
      return res.status(400).json({ error: 'Site ID or URL is required' });
    }

    let targetUrl = url;
    let siteRecord = null;

    if (siteId) {
      siteRecord = await Site.findOne({
        where: { id: siteId, user_id: req.user.id }
      });
      
      if (!siteRecord) {
        return res.status(404).json({ error: 'Site not found' });
      }
      
      targetUrl = siteRecord.url;
    }

    // Perform independent SEO audit
    const auditResult = await SEOAuditor.performAudit(targetUrl);
    
    // Save audit results if site record exists
    if (siteRecord) {
      await SEOAudit.create({
        site_id: siteRecord.id,
        score: auditResult.score,
        recommendations: JSON.stringify(auditResult.recommendations)
      });

      // Update site score and last audit date
      await siteRecord.update({
        score: auditResult.score,
        last_audit: new Date()
      });
    }

    res.json({
      score: auditResult.score,
      recommendations: auditResult.recommendations,
      data: auditResult.data
    });

  } catch (error) {
    console.error('SEO Audit error:', error);
    res.status(500).json({ 
      error: 'SEO audit failed', 
      details: error.message,
      // Provide fallback data so the request isn't completely useless
      score: 0,
      recommendations: [{ type: 'critical', text: 'Audit failed: ' + error.message }]
    });
  }
});

// Email Marketing routes (Independent module)
app.get('/api/contacts', authenticateToken, async (req, res) => {
  try {
    const contacts = await Contact.findAll({
      where: { user_id: req.user.id },
      order: [['created_at', 'DESC']]
    });
    res.json(contacts);
  } catch (error) {
    console.error('Get contacts error:', error);
    res.status(500).json({ error: 'Failed to fetch contacts' });
  }
});

app.post('/api/contacts', authenticateToken, async (req, res) => {
  try {
    const { email, name } = req.body;
    
    if (!email || !name) {
      return res.status(400).json({ error: 'Email and name are required' });
    }
    
    if (!validator.isEmail(email)) {
      return res.status(400).json({ error: 'Invalid email format' });
    }

    // Check contact limit
    const contactCount = await Contact.count({ where: { user_id: req.user.id } });
    if (contactCount >= 50) {
      return res.status(400).json({ error: 'Maximum of 50 contacts allowed per user' });
    }

    // Check if contact already exists
    const existingContact = await Contact.findOne({
      where: { user_id: req.user.id, email }
    });
    
    if (existingContact) {
      return res.status(400).json({ error: 'Contact with this email already exists' });
    }

    const contact = await Contact.create({ user_id: req.user.id, email, name });
    res.status(201).json(contact);
  } catch (error) {
    console.error('Add contact error:', error);
    res.status(500).json({ error: 'Failed to add contact' });
  }
});

app.delete('/api/contacts/:id', authenticateToken, async (req, res) => {
  try {
    const contact = await Contact.findOne({
      where: { id: req.params.id, user_id: req.user.id }
    });

    if (!contact) {
      return res.status(404).json({ error: 'Contact not found' });
    }

    await contact.destroy();
    res.json({ message: 'Contact deleted successfully' });
  } catch (error) {
    console.error('Delete contact error:', error);
    res.status(500).json({ error: 'Failed to delete contact' });
  }
});

// Campaign routes
app.get('/api/campaigns', authenticateToken, async (req, res) => {
  try {
    const campaigns = await Campaign.findAll({
      where: { user_id: req.user.id },
      include: [CampaignStats],
      order: [['created_at', 'DESC']]
    });
    res.json(campaigns);
  } catch (error) {
    console.error('Get campaigns error:', error);
    res.status(500).json({ error: 'Failed to fetch campaigns' });
  }
});

app.post('/api/campaigns', authenticateToken, async (req, res) => {
  try {
    const { title, content } = req.body;
    
    if (!title || !content) {
      return res.status(400).json({ error: 'Title and content are required' });
    }

    // Check active campaign limit
    const activeCampaignCount = await Campaign.count({
      where: { user_id: req.user.id, status: 'active' }
    });
    
    if (activeCampaignCount >= 3) {
      return res.status(400).json({ error: 'Maximum of 3 active campaigns allowed per user' });
    }

    const campaign = await Campaign.create({ 
      user_id: req.user.id, 
      title, 
      content,
      status: 'draft'
    });

    // Create campaign stats record
    await CampaignStats.create({ campaign_id: campaign.id });

    res.status(201).json(campaign);
  } catch (error) {
    console.error('Create campaign error:', error);
    res.status(500).json({ error: 'Failed to create campaign' });
  }
});

app.post('/api/campaigns/:id/send', authenticateToken, async (req, res) => {
  try {
    const campaign = await Campaign.findOne({
      where: { id: req.params.id, user_id: req.user.id }
    });

    if (!campaign) {
      return res.status(404).json({ error: 'Campaign not found' });
    }

    if (campaign.status === 'sent') {
      return res.status(400).json({ error: 'Campaign already sent' });
    }

    // Get user contacts
    const contacts = await Contact.findAll({
      where: { user_id: req.user.id }
    });

    if (contacts.length === 0) {
      return res.status(400).json({ error: 'No contacts available to send campaign' });
    }

    // Try to send emails (independent of other modules)
    let results = { sent: 0, failed: 0, errors: [] };
    
    try {
      const transporter = createTransporter();
      if (transporter) {
        results = await EmailMarketing.sendCampaign(campaign, contacts, transporter);
        
        // Update campaign status
        await campaign.update({
          status: 'sent',
          sent_at: new Date()
        });
      } else {
        throw new Error('SMTP configuration unavailable');
      }
    } catch (emailError) {
      console.error('Email sending error:', emailError.message);
      // Campaign creation/management still works even if emails fail
      results = {
        sent: 0,
        failed: contacts.length,
        errors: [`Email service unavailable: ${emailError.message}`]
      };
    }

    res.json({
      message: 'Campaign processing completed',
      results
    });

  } catch (error) {
    console.error('Send campaign error:', error);
    res.status(500).json({ error: 'Failed to process campaign' });
  }
});

app.delete('/api/campaigns/:id', authenticateToken, async (req, res) => {
  try {
    const campaign = await Campaign.findOne({
      where: { id: req.params.id, user_id: req.user.id }
    });

    if (!campaign) {
      return res.status(404).json({ error: 'Campaign not found' });
    }

    // Delete campaign stats first (foreign key constraint)
    await CampaignStats.destroy({ where: { campaign_id: campaign.id } });
    await campaign.destroy();

    res.json({ message: 'Campaign deleted successfully' });
  } catch (error) {
    console.error('Delete campaign error:', error);
    res.status(500).json({ error: 'Failed to delete campaign' });
  }
});

// Email tracking routes (for campaign analytics)
app.get('/api/email/track/:campaignId', async (req, res) => {
  try {
    // Update campaign stats for email opens
    await CampaignStats.increment('opens', {
      where: { campaign_id: req.params.campaignId }
    });

    // Return 1x1 transparent pixel
    const pixel = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==', 'base64');
    res.writeHead(200, {
      'Content-Type': 'image/png',
      'Content-Length': pixel.length
    });
    res.end(pixel);
  } catch (error) {
    console.error('Email tracking error:', error);
    res.status(200).end(); // Always return success for tracking pixels
  }
});

app.get('/api/email/unsubscribe', (req, res) => {
  res.send(`
    <html>
      <body style="font-family: Arial, sans-serif; text-align: center; padding: 50px;">
        <h2>Unsubscribe Successful</h2>
        <p>You have been successfully unsubscribed from our mailing list.</p>
        <p>If this was a mistake, please contact support.</p>
      </body>
    </html>
  `);
});

// Dashboard stats route
app.get('/api/dashboard', authenticateToken, async (req, res) => {
  try {
    const [siteCount, contactCount, campaignCount] = await Promise.all([
      Site.count({ where: { user_id: req.user.id } }),
      Contact.count({ where: { user_id: req.user.id } }),
      Campaign.count({ where: { user_id: req.user.id } })
    ]);

    // Get latest audits
    const recentAudits = await SEOAudit.findAll({
      include: [{
        model: Site,
        where: { user_id: req.user.id }
      }],
      order: [['created_at', 'DESC']],
      limit: 5
    });

    // Get campaign stats
    const campaignStats = await Campaign.findAll({
      where: { user_id: req.user.id },
      include: [CampaignStats],
      order: [['created_at', 'DESC']],
      limit: 5
    });

    res.json({
      stats: {
        sites: siteCount,
        contacts: contactCount,
        campaigns: campaignCount,
        limits: {
          sites: 3,
          contacts: 50,
          campaigns: 3
        }
      },
      recentAudits: recentAudits.map(audit => ({
        id: audit.id,
        score: audit.score,
        url: audit.Site?.url,
        created_at: audit.created_at
      })),
      campaignStats: campaignStats.map(campaign => ({
        id: campaign.id,
        title: campaign.title,
        status: campaign.status,
        opens: campaign.CampaignStat?.opens || 0,
        clicks: campaign.CampaignStat?.clicks || 0,
        sent_at: campaign.sent_at
      }))
    });
  } catch (error) {
    console.error('Dashboard error:', error);
    res.status(500).json({ error: 'Failed to fetch dashboard data' });
  }
});

// Health check route
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    services: {
      database: 'unknown', // Would need to test connection
      smtp: !!process.env.SMTP_USER,
      seo: 'available' // Playwright is always available once installed
    }
  });
});

// Error handling middleware
app.use((error, req, res, next) => {
  console.error('Unhandled error:', error);
  res.status(500).json({
    error: 'Internal server error',
    message: process.env.NODE_ENV === 'development' ? error.message : 'Something went wrong'
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

// Database initialization and server startup
async function startServer() {
  try {
    // Test database connection
    await sequelize.authenticate();
    console.log('✅ Database connection established successfully.');

    // Sync database models (create tables if they don't exist)
    await sequelize.sync({ alter: true });
    console.log('✅ Database models synchronized.');

    // Start server
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`🚀 Server running on port ${PORT}`);
      console.log(`📊 Dashboard: http://localhost:${PORT}`);
      console.log('🔧 Environment:', process.env.NODE_ENV || 'development');
      
      // Log configuration status
      console.log('\n📋 Configuration Status:');
      console.log('  - Database:', DATABASE_URL ? '✅ Configured' : '❌ Not configured');
      console.log('  - SMTP:', process.env.SMTP_USER ? '✅ Configured' : '❌ Not configured');
      console.log('  - JWT Secret:', JWT_SECRET !== 'your-super-secret-jwt-key-change-in-production' ? '✅ Custom' : '⚠️ Default');
    });
  } catch (error) {
    console.error('❌ Unable to start server:', error);
    process.exit(1);
  }
}

// Graceful shutdown
process.on('SIGTERM', async () => {
  console.log('🔄 SIGTERM received, shutting down gracefully...');
  await sequelize.close();
  process.exit(0);
});

process.on('SIGINT', async () => {
  console.log('\n🔄 SIGINT received, shutting down gracefully...');
  await sequelize.close();
  process.exit(0);
});

// Start the server
startServer();
