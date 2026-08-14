ALTER TABLE `reconEntities` MODIFY COLUMN `metadataJson` mediumtext;--> statement-breakpoint
ALTER TABLE `reconEvents` MODIFY COLUMN `payloadJson` mediumtext;--> statement-breakpoint
ALTER TABLE `reconRuns` MODIFY COLUMN `summary` mediumtext;--> statement-breakpoint
ALTER TABLE `reconRuns` MODIFY COLUMN `resultsJson` mediumtext;