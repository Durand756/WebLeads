require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Sequelize, DataTypes, Op } = require('sequelize');
const sgMail = require('@sendgrid/mail');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Configuration
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.static('public'));
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

// Configuration base de données
const sequelize = new Sequelize(process.env.DATABASE_URL || 'mysql://user:password@localhost:3306/seo_saas', {
  dialect: 'mysql',
  logging: false,
  dialectOptions: process.env.NODE_ENV === 'production' ? {
    ssl: {
      require: true,
      rejectUnauthorized: false
    }
  } : {}
});

// Modèles
const User = sequelize.define('User', {
  name: { type: DataTypes.STRING, allowNull: false },
  email: { type: DataTypes.STRING, unique: true, allowNull: false },
  password_hash: { type: DataTypes.STRING, allowNull: false }
});

const Site = sequelize.define('Site', {
  url: { type: DataTypes.STRING, allowNull: false },
  score: { type: DataTypes.INTEGER, defaultValue: 0 },
  last_audit: { type: DataTypes.DATE, defaultValue: DataTypes.NOW }
});

const SeoAudit = sequelize.define('SeoAudit', {
  score: { type: DataTypes.INTEGER, allowNull: false },
  recommendations: { type: DataTypes.JSON, allowNull: false }
});

const Contact = sequelize.define('Contact', {
  email: { type: DataTypes.STRING, allowNull: false },
  name: { type: DataTypes.STRING, allowNull: false }
});

const Campaign = sequelize.define('Campaign', {
  title: { type: DataTypes.STRING, allowNull: false },
  content: { type: DataTypes.TEXT, allowNull: false },
  status: { type: DataTypes.ENUM('draft', 'sent', 'active'), defaultValue: 'draft' },
  sent_at: { type: DataTypes.DATE }
});

const CampaignStats = sequelize.define('CampaignStats', {
  opens: { type: DataTypes.INTEGER, defaultValue: 0 },
  clicks: { type: DataTypes.INTEGER, defaultValue: 0 },
  unsubscribes: { type: DataTypes.INTEGER, defaultValue: 0 }
});

// Relations
User.hasMany(Site);
Site.belongsTo(User);
Site.hasMany(SeoAudit);
SeoAudit.belongsTo(Site);
User.hasMany(Contact);
Contact.belongsTo(User);
User.hasMany(Campaign);
Campaign.belongsTo(User);
Campaign.hasOne(CampaignStats);
CampaignStats.belongsTo(Campaign);

// Middleware d'authentification
const auth = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Token manquant' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Token invalide' });
  }
};

// Routes d'authentification
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
      return res.status(400).json({ error: 'Tous les champs sont requis' });
    }

    const existingUser = await User.findOne({ where: { email } });
    if (existingUser) {
      return res.status(400).json({ error: 'Email déjà utilisé' });
    }

    const password_hash = await bcrypt.hash(password, 10);
    const user = await User.create({ name, email, password_hash });
    
    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '24h' });
    res.json({ token, user: { id: user.id, name: user.name, email: user.email } });
  } catch (err) {
    res.status(500).json({ error: 'Erreur serveur', details: err.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ where: { email } });
    
    if (!user || !await bcrypt.compare(password, user.password_hash)) {
      return res.status(401).json({ error: 'Identifiants invalides' });
    }

    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '24h' });
    res.json({ token, user: { id: user.id, name: user.name, email: user.email } });
  } catch (err) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// Routes SEO
app.get('/api/sites', auth, async (req, res) => {
  try {
    const sites = await Site.findAll({
      where: { UserId: req.user.id },
      include: [{ model: SeoAudit, limit: 1, order: [['createdAt', 'DESC']] }]
    });
    res.json(sites);
  } catch (err) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.post('/api/sites', auth, async (req, res) => {
  try {
    const { url } = req.body;
    if (!url) return res.status(400).json({ error: 'URL requise' });

    const siteCount = await Site.count({ where: { UserId: req.user.id } });
    if (siteCount >= 3) {
      return res.status(400).json({ error: 'Limite de 3 sites atteinte' });
    }

    const site = await Site.create({ url, UserId: req.user.id });
    res.json(site);
  } catch (err) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.post('/api/audit', auth, async (req, res) => {
  try {
    const { siteId } = req.body;
    const site = await Site.findOne({ where: { id: siteId, UserId: req.user.id } });
    
    if (!site) return res.status(404).json({ error: 'Site non trouvé' });

    // Simulation d'audit SEO (remplace par vraie logique Lighthouse/Puppeteer)
    const score = Math.floor(Math.random() * 40) + 60; // Score entre 60-100
    const recommendations = [
      'Optimiser les balises title et meta description',
      'Améliorer la vitesse de chargement',
      'Ajouter du contenu de qualité',
      'Optimiser les images avec attributs alt',
      'Créer un sitemap XML'
    ];

    const audit = await SeoAudit.create({
      score,
      recommendations: recommendations.slice(0, Math.floor(Math.random() * 3) + 2),
      SiteId: siteId
    });

    await site.update({ score, last_audit: new Date() });
    
    res.json({ audit, site: await site.reload() });
  } catch (err) {
    res.status(500).json({ error: 'Erreur lors de l\'audit' });
  }
});

// Routes Email Marketing
app.get('/api/contacts', auth, async (req, res) => {
  try {
    const contacts = await Contact.findAll({ where: { UserId: req.user.id } });
    res.json(contacts);
  } catch (err) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.post('/api/contacts', auth, async (req, res) => {
  try {
    const { email, name } = req.body;
    if (!email || !name) return res.status(400).json({ error: 'Email et nom requis' });

    const contactCount = await Contact.count({ where: { UserId: req.user.id } });
    if (contactCount >= 50) {
      return res.status(400).json({ error: 'Limite de 50 contacts atteinte' });
    }

    const contact = await Contact.create({ email, name, UserId: req.user.id });
    res.json(contact);
  } catch (err) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.get('/api/campaigns', auth, async (req, res) => {
  try {
    const campaigns = await Campaign.findAll({
      where: { UserId: req.user.id },
      include: [CampaignStats]
    });
    res.json(campaigns);
  } catch (err) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.post('/api/campaigns', auth, async (req, res) => {
  try {
    const { title, content } = req.body;
    if (!title || !content) return res.status(400).json({ error: 'Titre et contenu requis' });

    const activeCampaigns = await Campaign.count({
      where: { UserId: req.user.id, status: 'active' }
    });
    
    if (activeCampaigns >= 3) {
      return res.status(400).json({ error: 'Limite de 3 campagnes actives atteinte' });
    }

    const campaign = await Campaign.create({ title, content, UserId: req.user.id });
    await CampaignStats.create({ CampaignId: campaign.id });
    
    res.json(campaign);
  } catch (err) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.post('/api/campaigns/:id/send', auth, async (req, res) => {
  try {
    const campaign = await Campaign.findOne({
      where: { id: req.params.id, UserId: req.user.id }
    });
    
    if (!campaign) return res.status(404).json({ error: 'Campagne non trouvée' });
    if (campaign.status === 'sent') return res.status(400).json({ error: 'Campagne déjà envoyée' });

    const contacts = await Contact.findAll({ where: { UserId: req.user.id } });
    
    if (contacts.length === 0) {
      return res.status(400).json({ error: 'Aucun contact trouvé' });
    }

    // Envoi via SendGrid
    const msgs = contacts.map(contact => ({
      to: contact.email,
      from: process.env.FROM_EMAIL || 'noreply@yourdomain.com',
      subject: campaign.title,
      html: `
        <div>
          <p>Bonjour ${contact.name},</p>
          ${campaign.content}
          <br><br>
          <small><a href="#unsubscribe">Se désabonner</a></small>
        </div>
      `
    }));

    try {
      await sgMail.send(msgs);
      await campaign.update({ status: 'sent', sent_at: new Date() });
      res.json({ message: `Campagne envoyée à ${contacts.length} contacts` });
    } catch (sgError) {
      console.error('SendGrid Error:', sgError);
      res.status(400).json({ error: 'Erreur envoi email', details: sgError.message });
    }
  } catch (err) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// Dashboard stats
app.get('/api/dashboard/stats', auth, async (req, res) => {
  try {
    const sitesCount = await Site.count({ where: { UserId: req.user.id } });
    const contactsCount = await Contact.count({ where: { UserId: req.user.id } });
    const campaignsCount = await Campaign.count({ where: { UserId: req.user.id } });
    
    const avgScore = await Site.findOne({
      where: { UserId: req.user.id },
      attributes: [[sequelize.fn('AVG', sequelize.col('score')), 'avgScore']]
    });

    res.json({
      sites: sitesCount,
      contacts: contactsCount,
      campaigns: campaignsCount,
      avgSeoScore: Math.round(avgScore?.dataValues.avgScore || 0)
    });
  } catch (err) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// Route de base
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Initialisation de la base de données et démarrage du serveur
const init = async () => {
  try {
    await sequelize.authenticate();
    console.log('✅ Connexion à la base de données réussie');
    
    await sequelize.sync({ alter: true });
    console.log('✅ Tables synchronisées');
    
    app.listen(PORT, () => {
      console.log(`🚀 Serveur démarré sur le port ${PORT}`);
      console.log(`📱 Application disponible sur http://localhost:${PORT}`);
    });
  } catch (err) {
    console.error('❌ Erreur de démarrage:', err);
    process.exit(1);
  }
};

init();
