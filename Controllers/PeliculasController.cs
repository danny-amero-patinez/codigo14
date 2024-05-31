using System.Security.Claims;
using frontendnet.Models;
using frontendnet.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.Mvc.Rendering;

namespace frontendnet;

[Authorize(Roles = "Administrador, Usuario")]
public class PeliculasController(PeliculasClientService peliculas, CategoriasClientService categorias) : Controller
{
    public async Task<IActionResult> Index(string? s)
    {
        List<Pelicula>? lista = [];
        try
        {
            lista = await peliculas.GetAsync(s);
        }
        catch (HttpRequestException ex)
        {
            if (ex.StatusCode == System.Net.HttpStatusCode.Unauthorized)
            return RedirectToAction("Salir", "Auth");
        }
        if (User.FindFirstValue(ClaimTypes.Role) == "Administrador")
        ViewBag.SoloAdmin = true;

        ViewBag.search = s;
        return View(lista);
    }

    public async Task<IActionResult> Detalle(int id)
    {
        Pelicula? item = null;
        try
        {
            item = await peliculas.GetAsync(id);
            if (item == null) return NotFound();
        }
        catch (HttpRequestException ex)
        {
            if (ex.StatusCode == System.Net.HttpStatusCode.Unauthorized)
            return RedirectToAction("Salir", "Auth");
        }
        return View(item);
    }

    [Authorize(Roles = "Administrador")]
    public IActionResult Crear()
    {
        return View();
    }

    [HttpPost]
    [Authorize(Roles = "Administrador")]
    public async Task<IActionResult> CrearAsync(Pelicula itemToCreate)
    {
        if (ModelState.IsValid)
        {
            try
            {
                await peliculas.PostAsync(itemToCreate);
                return RedirectToAction(nameof(Index));
            }
            catch (HttpRequestException ex)
            {
                if (ex.StatusCode == System.Net.HttpStatusCode.Unauthorized)
                return RedirectToAction("Salir", "Auth");
            }
        }

        ModelState.AddModelError("Nombre", "No ha sido posible realizar la acción. Intente nuevamente.");
        return View(itemToCreate);
    }

    [Authorize(Roles = "Administrador")]
    public async Task<IActionResult> EditarAsync(int id)
    {
        Pelicula? itemToEdit = null;
        try
        {
            itemToEdit = await peliculas.GetAsync(id);
            if (itemToEdit == null) return NotFound();
        }
        catch (HttpRequestException ex)
        {
            if (ex.StatusCode == System.Net.HttpStatusCode.Unauthorized)
            return RedirectToAction("Salir", "Auth");
        }
        return View(itemToEdit);
    }

    [HttpPost]
    [Authorize(Roles = "Administrador")]
    public async Task<IActionResult> EditarAsync(int id, Pelicula itemToEdit)
    {
        if (id != itemToEdit.PeliculaId) return NotFound();

        if (ModelState.IsValid)
        {
            try
            {
                await peliculas.PutAsync(itemToEdit);
                return RedirectToAction(nameof(Index));
            }
            catch (HttpRequestException ex)
            {
                if (ex.StatusCode == System.Net.HttpStatusCode.Unauthorized)
                return RedirectToAction("Salir", "Auth");
            }
        }

        ModelState.AddModelError("Nombre", "No ha sido posible realizar la acción. Intente nuevamente.");
        return View(itemToEdit);
    }

    [Authorize(Roles = "Administrador")]
    public async Task<IActionResult> Eliminar(int id, bool? showError = false)
    {
        Pelicula? itemToDelete = null;
        try
        {
            itemToDelete = await peliculas.GetAsync(id);
            if (itemToDelete == null) return NotFound();
        }
        catch (HttpRequestException ex)
        {
            if (ex.StatusCode == System.Net.HttpStatusCode.Unauthorized)
            return RedirectToAction("Salir", "Auth");
        }
        return View(itemToDelete);
    }

    [HttpPost]
    [Authorize(Roles = "Administrador")]
    public async Task<IActionResult> Eliminar(int id)
    {
        if (ModelState.IsValid)
        {
            try
            {
                await peliculas.DeleteAsync(id);
                return RedirectToAction(nameof(Index));
            }
            catch (HttpRequestException ex)
            {
                if (ex.StatusCode == System.Net.HttpStatusCode.Unauthorized)
                return RedirectToAction("Salir", "Auth");
            }
        }

        return RedirectToAction(nameof(Eliminar), new { id, showError = true });
    }

    [AcceptVerbs("GET", "POST")]
    [Authorize(Roles = "Administrador")]
    public IActionResult ValidaPoster(string poster)
    {
        if (Uri.IsWellFormedUriString(poster, UriKind.Absolute) || poster.Equals("N/A"))
            return Json(true);
        return Json(false);
    }

    [Authorize(Roles = "Administrador")]
    public async Task<IActionResult> Categorias(int id)
    {
        Pelicula? itemToView = null;
        try
        {
            itemToView = await peliculas.GetAsync(id);
            if (itemToView == null) return NotFound();
        }
        catch (HttpRequestException ex)
        {
            if (ex.StatusCode == System.Net.HttpStatusCode.Unauthorized)
            return RedirectToAction("Salir", "Auth");
        }
        ViewData["PeliculaId"] = itemToView?.PeliculaId;
        return View(itemToView);
    }
        
    [Authorize(Roles = "Administrador")]
    public async Task<IActionResult> CategoriasAgregar(int id)
    {
        PeliculaCategoria? itemToView =  null;
        try
        {
            Pelicula? pelicula = await peliculas.GetAsync(id);
            if (pelicula == null) return NotFound();

            await CategoriasDropDownListAsync();
            itemToView = new PeliculaCategoria {Pelicula = pelicula};
        }
        catch (HttpRequestException ex)
        {
            if (ex.StatusCode == System.Net.HttpStatusCode.Unauthorized)
            return RedirectToAction("Salir", "Auth");
        }
        return View(itemToView);
    }

    [HttpPost]
    [Authorize(Roles = "Administrador")]
    public async Task<IActionResult> CategoriasAgregar(int id, int categoriaid)
    {
        Pelicula? pelicula = null;
        if (ModelState.IsValid)
        {
            try
            {
                pelicula = await peliculas.GetAsync(id);
                if (pelicula == null) return NotFound();

                Categoria? categoria = await categorias.GetAsync(categoriaid);
                return RedirectToAction(nameof(Categorias), new { id });
            }
            catch (HttpRequestException ex)
            {
                if (ex.StatusCode == System.Net.HttpStatusCode.Unauthorized)
                return RedirectToAction("Salir", "Auth");
            }
        }

        ModelState.AddModelError("id", "No ha sido posible realizar la acción. Intente nuevamente.");
        await CategoriasDropDownListAsync();
        return View(new PeliculaCategoria {Pelicula = pelicula});
    }

    [Authorize(Roles = "Administrador")]
    public async Task<IActionResult> CategoriasRemover(int id, int categoriaid, bool? showError = false)
    {
        PeliculaCategoria? itemToView = null;
        try
        {
            Pelicula? pelicula = await peliculas.GetAsync(id);
            if (pelicula == null) return NotFound();

            Categoria? categoria = await categorias.GetAsync(categoriaid);
            if (categoria == null) return NotFound();

            itemToView = new PeliculaCategoria {Pelicula = pelicula, CategoriaId = categoriaid, Nombre = categoria.Nombre};

            if (showError.GetValueOrDefault())
                ViewData["ErrorMessage"] = "No ha sido posible realizar la acción. Intente nuevamente.";
        }
        catch (HttpRequestException ex)
        {
            if (ex.StatusCode == System.Net.HttpStatusCode.Unauthorized)
            return RedirectToAction("Salir", "Auth");
        }
        return View(itemToView);
    }

    [HttpPost]
    [Authorize(Roles = "Administrador")]
    public async Task<IActionResult> CategoriasRemover(int id, int categoriaid)
    {
        if (ModelState.IsValid)
        {
            try
            {
                await peliculas.DeleteAsync(id, categoriaid);
                return RedirectToAction(nameof(Categorias), new { id });
            }
            catch (HttpRequestException ex)
            {
                if (ex.StatusCode == System.Net.HttpStatusCode.Unauthorized)
                return RedirectToAction("Salir", "Auth");
            }
        }

        return RedirectToAction(nameof(CategoriasRemover), new { id, categoriaid, showError = true });
    }

    private async Task CategoriasDropDownListAsync(object? itemSeleccionado = null)
    {
        var listado = await categorias.GetAsync();
        ViewBag.Categoria = new SelectList(listado, "CategoriaId", "Nombre", itemSeleccionado);
    }
    
}