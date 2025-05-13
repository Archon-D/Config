// scripts/update-icon-json.js
const fs = require('fs');
const path = require('path');

const ICON_FOLDER = path.join(__dirname, '../icon/icons');
const JSON_PATH = path.join(__dirname, '../icon/icon.json');

// 获取 GitHub 相关环境变量
const REPO = process.env.GITHUB_REPOSITORY;
const BRANCH = process.env.GITHUB_REF_NAME || 'main';

function generateIconList() {
  const files = fs.readdirSync(ICON_FOLDER).filter(file => /\.(png|jpg|jpeg|svg)$/i.test(file));

  const icons = files.map(file => {
    const name = path.parse(file).name;
    const url = `https://raw.githubusercontent.com/${REPO}/${BRANCH}/icon/icons/${file}`;
    return { names: name, url };
  });

  return icons;
}

function updateJsonFile(icons) {
  let data = {
    name: "图标",
    description: "",
    icons: icons
  };

  fs.writeFileSync(JSON_PATH, JSON.stringify(data, null, 2), 'utf8');
  console.log(`✅ Updated ${JSON_PATH} with ${icons.length} icons.`);
}

const icons = generateIconList();
updateJsonFile(icons);
