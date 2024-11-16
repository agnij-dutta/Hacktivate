"use client";
import Links from "@/constants/links";
import Image from "next/image";
import Link from "next/link";
import { usePathname } from "next/navigation";
import React from "react";

const NavBar = ({ fixed }: { fixed: boolean }) => {
  const navItems = [{ name: "Home", href: "/landing" }].concat(
    Links.map((item) => ({
      name: item[0].toUpperCase() + item.slice(1),
      href: "/" + item.toLowerCase(),
    }))
  );

  const currentPath = usePathname();
  function setLinkStyles(itemLink: string) {
    const baseStyle = "mt-10 p-5 text-l font-semibold";
    const baseColor = 'text-stone-400';
    const accentColor = "text-amber-300";
    // This is done to ensure Home doesnt get highlighted in other tabs
    // Determine if the link is active based on the current path
    const isRootPath = itemLink === "/landing";
    const isExactMatch = itemLink === currentPath;
    const isSubPath = !isRootPath && currentPath.startsWith(itemLink);

    // Link is active if it's either an exact match or a sub-path of the current path
    const isActive = isExactMatch || isSubPath;
    return `${baseStyle} ${isActive ? accentColor : "hover:text-amber-300"}`;
  }
  return (
    <div
      className={`flex items-center justify-between bg-stone-900/20 backdrop-blur-sm border-b border-stone-700/50 ${
        fixed ? "fixed top-0 left-0 w-full z-10" : ""
      }`}
    >
      <div className="p-3 px-8 flex items-center justify-center">
        <Image src="/images/logo.png" width={30} height={30} alt="Logo" />
        <h1 className="bg-gradient-to-b from-gray-100 to-neutral-400 inline-block text-transparent bg-clip-text font-bold text-2xl ml-3">Hacktivate</h1>
      </div>
      <div className="p-3 px-5">
        {navItems.map((item, index) => (
          <Link
            key={index}
            href={item.href}
            className={setLinkStyles(item.href)}
          >
            {item.name}
          </Link>
        ))}
      </div>
    </div>
  );
};

export default NavBar;
