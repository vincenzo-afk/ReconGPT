declare module "robots-parser" {
  type RobotsParser = {
    isAllowed: (url: string, userAgent?: string) => boolean | undefined;
  };
  const robotsParser: (robotsUrl: string, robotsText: string) => RobotsParser;
  export default robotsParser;
}
