-- deny marks a rule that takes flows out of every allow rather than adding
-- them.
ALTER TABLE rules ADD COLUMN deny boolean NOT NULL DEFAULT false;
