import type { Socials } from "./types";

export const SITE_URL = "https://1keii.vercel.app"; // Replace with your site url
export const SITE_TITLE = "k.eii";
export const SITE_DESCRIPTION = "Forensic research for fun";
export const SITE_LOGO = "/logo.svg";

export const SOCIALS: Socials = [
  {
    name: "Github",
    href: "https://github.com/jonscafe",
    linkTitle: ` ${SITE_TITLE} on Github`,
    active: true,
  },
  {
    name: "Facebook",
    href: "https://github.com/aryanjha256/verve",
    linkTitle: `${SITE_TITLE} on Facebook`,
    active: false,
  },
  {
    name: "Instagram",
    href: "https://github.com/aryanjha256/verve",
    linkTitle: `${SITE_TITLE} on Instagram`,
    active: false,
  },
  {
    name: "Twitter",
    href: "https://github.com/aryanjha256/verve",
    linkTitle: `${SITE_TITLE} on Twitter`,
    active: false,
  },
  {
    name: "LinkedIn",
    href: "https://linkedin.com/in/jomrbn",
    linkTitle: `${SITE_TITLE} on LinkedIn`,
    active: true,
  },
  {
    name: "Mail",
    href: "mailto:adipatibangsawan61@gmail.com",
    linkTitle: `Send an email to ${SITE_TITLE}`,
    active: false,
  },
];
