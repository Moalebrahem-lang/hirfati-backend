require('../loadEnv')();

const { connect, cols } = require('../db');
const { isCloudinaryConfigured, isDataImage, uploadImageDataUri, uploadImages } = require('../cloudinary');

const apply = process.argv.includes('--apply');
const limitArg = process.argv.find(arg => arg.startsWith('--limit='));
const limit = limitArg ? Math.max(1, Number(limitArg.split('=')[1]) || 0) : 0;

const stats = {
  jobsScanned: 0,
  jobsChanged: 0,
  messagesScanned: 0,
  messagesChanged: 0,
  usersScanned: 0,
  usersChanged: 0,
  skippedIdentityImages: true
};

function shouldStop(count) {
  return limit > 0 && count >= limit;
}

async function migrateJobs() {
  const cursor = cols().jobs.find({ photos: /^data:image\// });
  while (await cursor.hasNext()) {
    const job = await cursor.next();
    stats.jobsScanned += 1;
    const oldPhotos = Array.isArray(job.photos) ? job.photos : [];
    if (!oldPhotos.some(isDataImage)) continue;

    if (apply) {
      const photos = await uploadImages(oldPhotos, {
        folder: 'hirfati/jobs',
        publicId: `${job.clientId || 'unknown'}-${job.id}`
      });
      await cols().jobs.updateOne(
        { id: job.id },
        { $set: { photos, imageMigratedAt: Date.now(), imageMigrationProvider: 'cloudinary' } }
      );
    }
    stats.jobsChanged += 1;
    if (shouldStop(stats.jobsChanged)) return;
  }
}

async function migrateMessages() {
  const cursor = cols().messages.find({ image: /^data:image\// });
  while (await cursor.hasNext()) {
    const message = await cursor.next();
    stats.messagesScanned += 1;
    if (!isDataImage(message.image)) continue;

    if (apply) {
      const image = await uploadImageDataUri(message.image, {
        folder: 'hirfati/messages',
        publicId: `${message.senderId || 'unknown'}-${message.id}`
      });
      await cols().messages.updateOne(
        { id: message.id },
        { $set: { image, imageMigratedAt: Date.now(), imageMigrationProvider: 'cloudinary' } }
      );
    }
    stats.messagesChanged += 1;
    if (shouldStop(stats.messagesChanged)) return;
  }
}

async function migratePortfolioImages() {
  const cursor = cols().users.find({ 'portfolio.image': /^data:image\// });
  while (await cursor.hasNext()) {
    const user = await cursor.next();
    stats.usersScanned += 1;
    const portfolio = Array.isArray(user.portfolio) ? user.portfolio : [];
    if (!portfolio.some(item => isDataImage(item?.image))) continue;

    if (apply) {
      const migrated = [];
      for (let index = 0; index < portfolio.length; index += 1) {
        const item = portfolio[index] || {};
        migrated.push({
          ...item,
          image: isDataImage(item.image)
            ? await uploadImageDataUri(item.image, {
              folder: 'hirfati/portfolio',
              publicId: `${user.id}-${index + 1}`
            })
            : item.image
        });
      }
      await cols().users.updateOne(
        { id: user.id },
        { $set: { portfolio: migrated, imageMigratedAt: Date.now(), imageMigrationProvider: 'cloudinary' } }
      );
    }
    stats.usersChanged += 1;
    if (shouldStop(stats.usersChanged)) return;
  }
}

async function main() {
  await connect();
  if (apply && !isCloudinaryConfigured()) {
    throw new Error('Cloudinary variables are required for --apply.');
  }

  await migrateJobs();
  await migrateMessages();
  await migratePortfolioImages();

  console.log(JSON.stringify({
    mode: apply ? 'apply' : 'dry-run',
    ...stats,
    note: 'Identity verification images are intentionally skipped because they need private storage/signed delivery.'
  }, null, 2));
}

main()
  .then(() => process.exit(0))
  .catch(err => {
    console.error(err.message);
    process.exit(1);
  });
